#Requires -Version 5.1
<#
.SYNOPSIS
    Exchange Certificate Swap Tool - guided WPF GUI to replace the IIS/SMTP certificate
    on Exchange 2016/2019/SE mailbox servers from a PFX file.

.DESCRIPTION
    WHERE TO RUN: on any Exchange mailbox server (or a machine with the Exchange Management Tools), in an elevated
    Windows PowerShell 5.1 window or the Exchange Management Shell:

        powershell.exe -STA -ExecutionPolicy Bypass -File .\ExchangeCertTool.ps1

    Workflow (one tab per step):
      1. Servers & inventory  - read-only: lists mailbox servers and every Exchange certificate.
      2. New certificate      - read-only: opens the PFX, checks key/expiry/EKU/chain, checks that
                                every Exchange URL host name is covered, reports connectors that
                                pin the old certificate via TlsCertificateName.
      3. Import & enable      - imports the same PFX into every selected server, enables it for
                                IIS + SMTP. Keeps the internal transport certificate unless asked.
      4. Verify               - checks Exchange's view and the certificate actually served on
                                HTTPS 443 (and SMTP 25 STARTTLS, informational).
      5. Remove old           - optional; refuses to remove certificates still in use
                                (Auth, internal transport, IIS, pinned by connectors, or unverified server).

    "Dry run" is ON by default: every command is written to the log and nothing is changed.
    Every action is logged to .\logs\CertSwap_<timestamp>.log.

.PARAMETER LogDirectory
    Folder for log files. Default: <script folder>\logs

.PARAMETER LoadOnly
    Define functions and build the window without connecting to Exchange or showing it.
    For testing:  . .\ExchangeCertTool.ps1 -LoadOnly
#>
[CmdletBinding()]
param(
    [string]$LogDirectory,
    [switch]$LoadOnly
)

$ErrorActionPreference = 'Stop'
if (-not $LogDirectory) { $LogDirectory = Join-Path $PSScriptRoot 'logs' }

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'Run this tool in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7 - the Exchange cmdlets and WPF host require it.'
}

# WPF needs an STA thread. powershell.exe 5.1 is STA by default; relaunch if not.
if (-not $LoadOnly -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-LogDirectory', "`"$LogDirectory`"")
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $argList
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Data

# ---------------------------------------------------------------------------------------------
# State and logging
# ---------------------------------------------------------------------------------------------
$script:State = @{
    Servers      = @{}      # name -> @{ Fqdn; Version; InternalTransportThumb }
    Inventory    = @()
    AuthThumb    = $null
    PfxPath      = $null
    PfxPassword  = $null    # SecureString
    NewCert      = $null    # X509Certificate2 (leaf)
    NewThumb     = $null
    NewNames     = @()
    Validated    = $false
    MissingHosts = @()
    Verified     = @{}      # server -> $true when Exchange + HTTPS checks passed
}
$script:ui = $null
$script:Window = $null

if (-not (Test-Path -LiteralPath $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
$script:LogFile = Join-Path $LogDirectory ('CertSwap_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))

function Update-Ui {
    if ($script:Window) {
        $script:Window.Dispatcher.Invoke([Action] {}, [Windows.Threading.DispatcherPriority]::Background)
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK', 'CMD')][string]$Level = 'INFO'
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1,-5}] {2}' -f (Get-Date), $Level, $Message
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    if ($script:ui -and $script:ui.LogBox) {
        $script:ui.LogBox.AppendText($line + "`r`n")
        $script:ui.LogBox.ScrollToEnd()
        Update-Ui
    }
    else {
        $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } 'CMD' { 'Cyan' } default { 'Gray' } }
        Write-Host $line -ForegroundColor $color
    }
}

function Test-DryRun {
    if ($script:ui -and $script:ui.DryRunCheck) { return [bool]$script:ui.DryRunCheck.IsChecked }
    return $true
}

# Logs the command; executes it only when dry run is off.
function Invoke-Step {
    param([Parameter(Mandatory)][string]$Description, [Parameter(Mandatory)][scriptblock]$Action)
    if (Test-DryRun) {
        Write-Log "[DRY RUN] $Description" CMD
        return
    }
    Write-Log $Description CMD
    & $Action
}

function ConvertTo-DataTable {
    param([object[]]$InputObject, [Parameter(Mandatory)][string[]]$Columns)
    $dt = New-Object System.Data.DataTable
    foreach ($c in $Columns) { [void]$dt.Columns.Add($c, [string]) }
    foreach ($o in @($InputObject)) {
        if ($null -eq $o) { continue }
        $row = $dt.NewRow()
        foreach ($c in $Columns) {
            $v = $o.$c
            if ($null -eq $v) { $row[$c] = '' }
            elseif ($v -is [datetime]) { $row[$c] = $v.ToString('yyyy-MM-dd HH:mm') }
            else { $row[$c] = "$v" }
        }
        $dt.Rows.Add($row)
    }
    , $dt
}

function Confirm-Action {
    param([string]$Message, [string]$Title = 'Confirm')
    if (-not $script:Window) { return $false }
    $r = [System.Windows.MessageBox]::Show($script:Window, $Message, $Title,
        [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    return ($r -eq [System.Windows.MessageBoxResult]::Yes)
}

# ---------------------------------------------------------------------------------------------
# Certificate helpers (no Exchange needed)
# ---------------------------------------------------------------------------------------------
function Read-PfxFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][securestring]$Password)
    $plain = (New-Object System.Net.NetworkCredential('', $Password)).Password
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
    $coll = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    # EphemeralKeySet only: the private key stays in memory and is never persisted to any
    # key store, CSP/KSP or smart card/token (e.g. SafeNet eToken). No fallback on purpose.
    if (-not [Enum]::IsDefined($flags, 'EphemeralKeySet')) {
        throw '.NET Framework 4.7.2 or newer is required to inspect the PFX without persisting its private key.'
    }
    try { $coll.Import($Path, $plain, $flags::EphemeralKeySet) }
    finally { $plain = $null }
    foreach ($c in $coll) { $c }
}

function Get-CertSanNames {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $names = New-Object System.Collections.Generic.List[string]
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($ext) {
        foreach ($line in ($ext.Format($true) -split "`r?`n")) {
            # "DNS Name=mail.contoso.com" (English) / "DNS-Name=..." (other locales)
            if ($line -match '^\s*DNS[^=]*=\s*(.+?)\s*$') { $names.Add($Matches[1].ToLowerInvariant()) }
        }
    }
    , $names.ToArray()
}

function Test-HostCovered {
    param([string]$HostName, [string[]]$CertNames)
    $h = $HostName.ToLowerInvariant()
    foreach ($n in $CertNames) {
        $n = $n.ToLowerInvariant()
        if ($n -eq $h) { return $true }
        if ($n.StartsWith('*.')) {
            $suffix = $n.Substring(1)   # ".contoso.com"
            if ($h.EndsWith($suffix) -and $h.Length -gt $suffix.Length) {
                $label = $h.Substring(0, $h.Length - $suffix.Length)
                if ($label -notmatch '\.') { return $true }   # wildcard covers exactly one label
            }
        }
    }
    return $false
}

function ConvertTo-NormalizedDn {
    param([string]$Dn)
    if (-not $Dn) { return '' }
    return ((($Dn -split '\s*,\s*') -join ',').Trim()).ToLowerInvariant()
}

function Get-RemoteTlsCertificate {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [int]$Port = 443,
        [string]$SniName,
        [switch]$StartTls,
        [int]$TimeoutMs = 10000
    )
    if (-not $SniName) { $SniName = $HostName }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "Timeout connecting to ${HostName}:$Port" }
        $client.EndConnect($iar)
        $net = $client.GetStream()
        $net.ReadTimeout = $TimeoutMs
        $net.WriteTimeout = $TimeoutMs
        $banner = $null
        if ($StartTls) {
            $reader = New-Object System.IO.StreamReader($net, [System.Text.Encoding]::ASCII)
            $readReply = {
                $lines = New-Object System.Collections.Generic.List[string]
                while ($true) {
                    $l = $reader.ReadLine()
                    if ($null -eq $l) { throw 'SMTP connection closed by server' }
                    $lines.Add($l)
                    if ($l.Length -lt 4 -or $l[3] -ne '-') { break }
                }
                $lines.ToArray()
            }
            $send = { param($cmd) $b = [System.Text.Encoding]::ASCII.GetBytes("$cmd`r`n"); $net.Write($b, 0, $b.Length); $net.Flush() }
            $greet = @(& $readReply)
            if ($greet[0] -notmatch '^220') { throw "Unexpected SMTP banner: $($greet -join ' | ')" }
            $banner = $greet[0]
            & $send 'EHLO certcheck.local'
            $ehlo = @(& $readReply)
            if (-not ($ehlo -match 'STARTTLS')) { throw "Server did not offer STARTTLS. EHLO: $($ehlo -join ' | ')" }
            & $send 'STARTTLS'
            $st = @(& $readReply)
            if ($st[0] -notmatch '^220') { throw "STARTTLS rejected: $($st -join ' | ')" }
        }
        $script:__tlsPolicyErrors = $null
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $cert, $chain, $sslErrors)
            $script:__tlsPolicyErrors = $sslErrors
            return $true   # we only inspect the certificate; trust is reported, not enforced
        }
        $ssl = New-Object System.Net.Security.SslStream($net, $false, $callback)
        try {
            $ssl.AuthenticateAsClient($SniName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            $remote = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            [pscustomobject]@{
                Host         = $HostName
                Port         = $Port
                Thumbprint   = $remote.Thumbprint
                Subject      = $remote.Subject
                NotAfter     = $remote.NotAfter
                Protocol     = "$($ssl.SslProtocol)"
                PolicyErrors = "$($script:__tlsPolicyErrors)"
                Banner       = $banner
            }
        }
        finally { $ssl.Dispose() }
    }
    finally { $client.Close() }
}

# ---------------------------------------------------------------------------------------------
# Exchange helpers
# ---------------------------------------------------------------------------------------------
function Test-ExchangeAvailable { [bool](Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) }

function Assert-Exchange {
    if (-not (Test-ExchangeAvailable)) { throw 'Exchange cmdlets are not loaded. Run this tool on an Exchange server (or from the Exchange Management Shell).' }
}

function Assert-Validated {
    if (-not $script:State.Validated) { throw 'Validate the PFX on tab "2. New certificate" first.' }
}

# Works with live (snap-in) and deserialized (remote EMS) objects.
function Get-ServiceList { param($ExCert) @(("$($ExCert.Services)" -split '\s*,\s*') | Where-Object { $_ -and $_ -ne 'None' }) }
function Get-ExCertDomains { param($ExCert) @($ExCert.CertificateDomains | ForEach-Object { "$_" }) }

function Get-SelectedServers {
    if (-not $script:ui) { return @() }
    @($script:ui.ServerList.SelectedItems | ForEach-Object { "$_" })
}

function Get-ExchangeCertSafe {
    param([string]$Server, [string]$Thumbprint)
    try { return (Get-ExchangeCertificate -Server $Server -Thumbprint $Thumbprint -ErrorAction Stop) } catch { return $null }
}

function Update-ServerList {
    Assert-Exchange
    $servers = @(Get-ExchangeServer | Where-Object { "$($_.ServerRole)" -match 'Mailbox' } | Sort-Object Name)
    $script:ui.ServerList.Items.Clear()
    $script:State.Servers = @{}
    foreach ($s in $servers) {
        $name = "$($s.Name)"
        $script:State.Servers[$name] = @{ Fqdn = "$($s.Fqdn)"; Version = "$($s.AdminDisplayVersion)"; InternalTransportThumb = $null }
        [void]$script:ui.ServerList.Items.Add($name)
        Write-Log ('Found mailbox server {0} ({1}, {2})' -f $name, $s.Fqdn, $s.AdminDisplayVersion)
    }
    $script:ui.ServerList.SelectAll()
    if (-not $servers) { Write-Log 'No Exchange mailbox servers found.' WARN }
}

function Update-Inventory {
    Assert-Exchange
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    try {
        $script:State.AuthThumb = "$((Get-AuthConfig).CurrentCertificateThumbprint)"
        Write-Log "Auth (OAuth) certificate: $($script:State.AuthThumb)"
    }
    catch { Write-Log "Get-AuthConfig failed: $($_.Exception.Message)" WARN }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($s in $servers) {
        try {
            $ts = Get-TransportService -Identity $s
            $script:State.Servers[$s].InternalTransportThumb = "$($ts.InternalTransportCertificateThumbprint)"
            Write-Log "${s}: internal transport certificate $($ts.InternalTransportCertificateThumbprint)"
        }
        catch { Write-Log "${s}: Get-TransportService failed: $($_.Exception.Message)" WARN }
        try {
            foreach ($c in @(Get-ExchangeCertificate -Server $s)) {
                $thumb = "$($c.Thumbprint)"
                $roles = @()
                if ($thumb -eq $script:State.AuthThumb) { $roles += 'Auth' }
                if ($thumb -eq $script:State.Servers[$s].InternalTransportThumb) { $roles += 'InternalTransport' }
                if ($script:State.NewThumb -and $thumb -eq $script:State.NewThumb) { $roles += 'NEW' }
                $notAfter = [datetime]$c.NotAfter
                $rows.Add([pscustomobject]@{
                        Server     = $s
                        Thumbprint = $thumb
                        Subject    = "$($c.Subject)"
                        Services   = (Get-ServiceList $c) -join ','
                        NotAfter   = $notAfter
                        DaysLeft   = [int][math]::Floor(($notAfter - (Get-Date)).TotalDays)
                        SelfSigned = "$($c.IsSelfSigned)"
                        Role       = $roles -join ','
                        Issuer     = "$($c.Issuer)"
                        Domains    = (Get-ExCertDomains $c) -join ', '
                    })
            }
        }
        catch { Write-Log "${s}: Get-ExchangeCertificate failed: $($_.Exception.Message)" ERROR }
    }
    $script:State.Inventory = $rows.ToArray()
    $script:ui.InventoryGrid.ItemsSource = (ConvertTo-DataTable $rows.ToArray() @('Server', 'Thumbprint', 'Subject', 'Services', 'NotAfter', 'DaysLeft', 'SelfSigned', 'Role', 'Issuer', 'Domains')).DefaultView
    Write-Log ("Inventory: {0} certificate(s) on {1} server(s)." -f $rows.Count, $servers.Count) OK
}

function Get-ExchangeHostNames {
    param([string[]]$Servers)
    $found = New-Object System.Collections.Generic.List[object]
    $add = {
        param($Source, $Server, $Url)
        if (-not "$Url") { return }
        try {
            $h = ([uri]"$Url").Host
            if ($h) { $found.Add([pscustomobject]@{ Host = $h.ToLowerInvariant(); Source = $Source; Server = $Server }) }
        }
        catch { }
    }
    $vdirCmds = 'Get-OwaVirtualDirectory', 'Get-EcpVirtualDirectory', 'Get-WebServicesVirtualDirectory',
    'Get-OabVirtualDirectory', 'Get-ActiveSyncVirtualDirectory', 'Get-MapiVirtualDirectory'
    foreach ($s in $Servers) {
        foreach ($cmd in $vdirCmds) {
            try {
                foreach ($v in @(& $cmd -Server $s -ADPropertiesOnly -ErrorAction Stop)) {
                    $short = $cmd -replace '^Get-|VirtualDirectory$', ''
                    & $add "$short internal" $s $v.InternalUrl
                    & $add "$short external" $s $v.ExternalUrl
                }
            }
            catch { Write-Log "${s}: $cmd failed: $($_.Exception.Message)" WARN }
        }
        try { & $add 'Autodiscover SCP' $s (Get-ClientAccessService -Identity $s -ErrorAction Stop).AutoDiscoverServiceInternalUri }
        catch { Write-Log "${s}: Get-ClientAccessService failed: $($_.Exception.Message)" WARN }
    }
    $found.ToArray()
}

function Get-ConnectorTlsReport {
    param([string[]]$Servers, $NewIssuer, $NewSubject, [object[]]$OldCerts)
    $newKey = (ConvertTo-NormalizedDn $NewIssuer) + '|' + (ConvertTo-NormalizedDn $NewSubject)
    $items = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($c in @(Get-SendConnector)) {
            if ("$($c.TlsCertificateName)") { $items.Add([pscustomobject]@{ Type = 'Send'; Identity = "$($c.Identity)"; Tls = "$($c.TlsCertificateName)" }) }
        }
    }
    catch { Write-Log "Get-SendConnector failed: $($_.Exception.Message)" WARN }
    foreach ($s in $Servers) {
        try {
            foreach ($c in @(Get-ReceiveConnector -Server $s)) {
                if ("$($c.TlsCertificateName)") { $items.Add([pscustomobject]@{ Type = 'Receive'; Identity = "$($c.Identity)"; Tls = "$($c.TlsCertificateName)" }) }
            }
        }
        catch { Write-Log "${s}: Get-ReceiveConnector failed: $($_.Exception.Message)" WARN }
    }
    foreach ($i in $items) {
        $issuer = ''; $subject = ''
        if ($i.Tls -match '^<I>(.*?)<S>(.*)$') { $issuer = $Matches[1]; $subject = $Matches[2] }
        $key = (ConvertTo-NormalizedDn $issuer) + '|' + (ConvertTo-NormalizedDn $subject)
        $matchNew = ($key -eq $newKey)
        $oldThumbs = @($OldCerts | Where-Object { ((ConvertTo-NormalizedDn $_.Issuer) + '|' + (ConvertTo-NormalizedDn $_.Subject)) -eq $key } |
                Select-Object -ExpandProperty Thumbprint -Unique)
        $tlsNew = ("<I>{0}<S>{1}" -f $NewIssuer, $NewSubject) -replace "'", "''"
        $setCmd = if ($i.Type -eq 'Send') { 'Set-SendConnector' } else { 'Set-ReceiveConnector' }
        if ($matchNew) { $status = 'OK - new certificate has the same issuer/subject, Exchange will pick it up' }
        elseif ($oldThumbs) { $status = 'ACTION - pinned to the OLD certificate; update before removing the old one' }
        else { $status = 'INFO - references a different certificate (not old, not new)' }
        $i | Add-Member -NotePropertyName MatchesNew -NotePropertyValue $matchNew
        $i | Add-Member -NotePropertyName OldThumbprints -NotePropertyValue ($oldThumbs -join ',')
        $i | Add-Member -NotePropertyName Status -NotePropertyValue $status
        $i | Add-Member -NotePropertyName FixCommand -NotePropertyValue ("{0} -Identity '{1}' -TlsCertificateName '{2}'" -f $setCmd, ($i.Identity -replace "'", "''"), $tlsNew)
    }
    $items.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Step 2: validate PFX
# ---------------------------------------------------------------------------------------------
function Reset-Validation {
    if ($script:State.Validated) { Write-Log 'PFX path or password changed - validation reset, please validate again.' WARN }
    $script:State.Validated = $false
    $script:State.NewCert = $null
    $script:State.NewThumb = $null
}

function Invoke-ValidatePfx {
    $path = $script:ui.PfxPathBox.Text.Trim().Trim('"')
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { throw "PFX file not found: '$path'" }
    $pw = $script:ui.PfxPasswordBox.SecurePassword
    Reset-Validation

    $sb = New-Object System.Text.StringBuilder
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $out = { param([string]$t = '') [void]$sb.AppendLine($t) }

    try { $certs = @(Read-PfxFile -Path $path -Password $pw) }
    catch { throw "Could not open PFX (wrong password or damaged file): $($_.Exception.Message)" }
    $leaf = $certs | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $leaf) { throw 'The PFX contains no certificate with a private key - Exchange cannot use it.' }
    $others = @($certs | Where-Object { $_.Thumbprint -ne $leaf.Thumbprint })

    $sanNames = Get-CertSanNames $leaf
    $cn = $leaf.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $allNames = @($sanNames)
    if ($cn -and ($allNames -notcontains $cn.ToLowerInvariant())) { $allNames += $cn.ToLowerInvariant() }
    $daysLeft = [int][math]::Floor(($leaf.NotAfter - (Get-Date)).TotalDays)

    & $out '=== CERTIFICATE ==='
    & $out "File        : $path"
    & $out "Subject     : $($leaf.Subject)"
    & $out "Issuer      : $($leaf.Issuer)"
    & $out "Thumbprint  : $($leaf.Thumbprint)"
    & $out ("Valid       : {0:yyyy-MM-dd} -> {1:yyyy-MM-dd}  ({2} days left)" -f $leaf.NotBefore, $leaf.NotAfter, $daysLeft)
    try { & $out ("Key         : {0} {1} bit" -f $leaf.PublicKey.Oid.FriendlyName, $leaf.PublicKey.Key.KeySize) }
    catch { & $out ("Key         : {0}" -f $leaf.PublicKey.Oid.FriendlyName) }
    & $out "Private key : present"
    & $out "Chain certs in PFX: $($others.Count)"
    & $out "SAN names   : $($sanNames -join ', ')"
    & $out ''

    if ($leaf.NotAfter -lt (Get-Date)) { $errors.Add('Certificate is EXPIRED.') }
    elseif ($leaf.NotBefore -gt (Get-Date)) { $errors.Add("Certificate is not valid yet (NotBefore $($leaf.NotBefore)).") }
    elseif ($daysLeft -lt 30) { $warnings.Add("Certificate expires in $daysLeft days.") }
    if (-not $sanNames) { $warnings.Add('Certificate has no Subject Alternative Names - modern clients ignore the CN.') }

    $eku = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if ($eku) {
        $ekuOids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
        if ($ekuOids -notcontains '1.3.6.1.5.5.7.3.1') { $errors.Add('Certificate lacks the Server Authentication EKU (1.3.6.1.5.5.7.3.1).') }
    }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    foreach ($o in $others) { [void]$chain.ChainPolicy.ExtraStore.Add($o) }
    if ($chain.Build($leaf)) { & $out 'Chain       : builds to a trusted root on this server' }
    else {
        $st = ($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; '
        $warnings.Add("Chain does not build to a trusted root on this server: $st")
    }
    & $out ''

    $script:State.MissingHosts = @()
    $servers = Get-SelectedServers
    if ((Test-ExchangeAvailable) -and $servers) {
        & $out "=== HOST NAMES USED BY EXCHANGE ($($servers -join ', ')) ==="
        $hosts = @(Get-ExchangeHostNames -Servers $servers)
        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($g in ($hosts | Group-Object Host | Sort-Object Name)) {
            $covered = Test-HostCovered -HostName $g.Name -CertNames $allNames
            $src = (@($g.Group | ForEach-Object { "$($_.Server):$($_.Source)" } | Select-Object -Unique) -join ', ')
            & $out ("  [{0}] {1,-35} {2}" -f $(if ($covered) { ' OK ' } else { 'MISS' }), $g.Name, $src)
            if (-not $covered) { $missing.Add($g.Name) }
        }
        if (-not $hosts) { $warnings.Add('No InternalUrl/ExternalUrl values found on the virtual directories.') }
        $script:State.MissingHosts = $missing.ToArray()
        if ($missing.Count) { $warnings.Add("Not covered by the certificate: $($missing -join ', ') - clients using these names will get certificate errors.") }
        $internalOnly = @($missing | Where-Object { $_ -match '\.(local|lan|internal|corp|intra)$' -or $_ -notmatch '\.' })
        if ($internalOnly) { $warnings.Add("Public CAs cannot issue certificates for $($internalOnly -join ', '). Point those InternalUrl values at a public name on the certificate (split DNS), e.g. Set-WebServicesVirtualDirectory -Identity '<server>\EWS (Default Web Site)' -InternalUrl https://mail.<domain>/EWS/Exchange.asmx") }

        try {
            foreach ($d in @(Get-AcceptedDomain)) {
                $ad = "autodiscover.$($d.DomainName)".ToLowerInvariant()
                if ($ad -notlike '*.*.*' -or $ad -like '*.local') { continue }
                if (-not (Test-HostCovered -HostName $ad -CertNames $allNames)) {
                    & $out "  [INFO] $ad not on certificate (fine if Autodiscover uses SRV records or another name)"
                }
            }
        }
        catch { Write-Log "Get-AcceptedDomain failed: $($_.Exception.Message)" WARN }
        & $out ''

        & $out '=== CURRENT CERTIFICATES ON THE SERVERS ==='
        if (-not $script:State.Inventory) { Update-Inventory }
        $inv = @($script:State.Inventory | Where-Object { $servers -contains $_.Server })
        foreach ($r in ($inv | Where-Object { $_.Services -match 'IIS' })) {
            & $out ("  {0,-10} IIS cert {1}  {2}  exp {3:yyyy-MM-dd}  self-signed={4}" -f $r.Server, $r.Thumbprint, $r.Subject, $r.NotAfter, $r.SelfSigned)
        }
        foreach ($s in $servers) {
            if ($inv | Where-Object { $_.Server -eq $s -and $_.Thumbprint -eq $leaf.Thumbprint }) {
                & $out "  $s already has the new certificate imported."
            }
        }
        if ($script:State.AuthThumb -eq $leaf.Thumbprint) { $warnings.Add('The new certificate is the current Auth (OAuth) certificate?!') }
        & $out ''

        & $out '=== CONNECTORS WITH TlsCertificateName ==='
        $oldCerts = @($inv | Where-Object { $_.SelfSigned -ne 'True' -and $_.Thumbprint -ne $leaf.Thumbprint })
        $conns = @(Get-ConnectorTlsReport -Servers $servers -NewIssuer $leaf.Issuer -NewSubject $leaf.Subject -OldCerts $oldCerts)
        if (-not $conns) { & $out '  None - no connector pins a certificate. Nothing to update.' }
        foreach ($c in $conns) {
            & $out ("  {0} connector '{1}'" -f $c.Type, $c.Identity)
            & $out ("      TlsCertificateName: {0}" -f $c.Tls)
            & $out ("      {0}" -f $c.Status)
            if (-not $c.MatchesNew) { & $out ("      To point it at the new cert (run manually after enabling): {0}" -f $c.FixCommand) }
        }
        if ($conns | Where-Object { $_.Status -like 'ACTION*' }) { $warnings.Add('One or more connectors pin the OLD certificate - see the connector section.') }
        & $out ''
    }
    else {
        & $out '(Exchange not available or no server selected - host name and connector checks skipped.)'
        $warnings.Add('Exchange checks were skipped.')
    }

    & $out '=== RESULT ==='
    foreach ($e in $errors) { & $out "  ERROR: $e" }
    foreach ($w in $warnings) { & $out "  WARN : $w" }
    if (-not $errors.Count) {
        & $out ('  Certificate can be imported.' + $(if ($warnings.Count) { ' Review the warnings first.' } else { '' }))
        $script:State.Validated = $true
        $script:State.NewCert = $leaf
        $script:State.NewThumb = $leaf.Thumbprint
        $script:State.NewNames = $allNames
        $script:State.PfxPath = $path
        $script:State.PfxPassword = $pw
        $script:State.Verified = @{}
    }
    else { & $out '  Certificate is NOT usable - fix the errors above.' }

    $report = $sb.ToString()
    $script:ui.ValidationBox.Text = $report
    foreach ($l in ($report -split "`r?`n")) { if ($l) { Add-Content -LiteralPath $script:LogFile -Value "    | $l" -Encoding UTF8 } }
    if ($errors.Count) { Write-Log "Validation FAILED: $($errors -join ' ')" ERROR }
    else { Write-Log ("Validation passed for {0} ({1} warning(s))." -f $leaf.Thumbprint, $warnings.Count) OK }
}

# ---------------------------------------------------------------------------------------------
# Step 3: import + enable
# ---------------------------------------------------------------------------------------------
function Invoke-ImportCertificate {
    Assert-Exchange; Assert-Validated
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    $thumb = $script:State.NewThumb
    $exportable = [bool]$script:ui.ExportableCheck.IsChecked
    $msg = "Import certificate`n  $($script:State.NewCert.Subject)`n  Thumbprint $thumb`n`ninto: $($servers -join ', ')"
    if ($script:State.MissingHosts.Count) { $msg += "`n`nWARNING: the certificate does NOT cover: $($script:State.MissingHosts -join ', ')" }
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Import certificate')) { Write-Log 'Import cancelled.' WARN; return }

    $bytes = [System.IO.File]::ReadAllBytes($script:State.PfxPath)
    $pw = $script:State.PfxPassword
    foreach ($s in $servers) {
        try {
            if (Get-ExchangeCertSafe -Server $s -Thumbprint $thumb) { Write-Log "${s}: certificate $thumb already present - import skipped." OK; continue }
            Invoke-Step "Import-ExchangeCertificate -Server $s -FileData <$($bytes.Length) bytes of $($script:State.PfxPath)> -Password <hidden> -PrivateKeyExportable:`$$exportable" {
                Import-ExchangeCertificate -Server $s -FileData $bytes -Password $pw -PrivateKeyExportable:$exportable -ErrorAction Stop | Out-Null
                $check = Get-ExchangeCertSafe -Server $s -Thumbprint $thumb
                if (-not $check) { throw 'Import returned no error, but the certificate is not visible on the server.' }
                Write-Log "${s}: imported. Services: $((Get-ServiceList $check) -join ',')" OK
            }
        }
        catch { Write-Log "${s}: import FAILED: $($_.Exception.Message)" ERROR }
    }
    if (-not (Test-DryRun)) { Update-Inventory }
}

function Invoke-EnableCertificate {
    Assert-Exchange; Assert-Validated
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    $thumb = $script:State.NewThumb
    $replaceInternal = [bool]$script:ui.ReplaceInternalCheck.IsChecked

    if (-not (Test-DryRun)) {
        $notImported = @($servers | Where-Object { -not (Get-ExchangeCertSafe -Server $_ -Thumbprint $thumb) })
        if ($notImported) { throw "Certificate is not imported on: $($notImported -join ', '). Run step A first." }
    }
    $msg = "Enable certificate $thumb for IIS + SMTP on: $($servers -join ', ')`n`n" +
    "- The HTTPS binding of the Default Web Site (443) switches to the new certificate immediately.`n" +
    "- The Exchange Back End site (444) is not touched.`n" +
    "- Internal transport certificate: $(if ($replaceInternal) { 'WILL BE REPLACED' } else { 'kept (restored if Exchange replaces it)' })`n" +
    "- The old certificate stays on the servers."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Enable certificate')) { Write-Log 'Enable cancelled.' WARN; return }

    foreach ($s in $servers) {
        try {
            $before = "$((Get-TransportService -Identity $s).InternalTransportCertificateThumbprint)"
            Write-Log "${s}: internal transport certificate before: $before"
            Invoke-Step "Enable-ExchangeCertificate -Server $s -Thumbprint $thumb -Services IIS,SMTP -Force" {
                Enable-ExchangeCertificate -Server $s -Thumbprint $thumb -Services IIS, SMTP -Force -ErrorAction Stop
            }
            if (Test-DryRun) {
                if (-not $replaceInternal) { Write-Log "[DRY RUN] ${s}: would restore internal transport certificate to $before if Enable-ExchangeCertificate replaced it." CMD }
                continue
            }
            $after = "$((Get-TransportService -Identity $s).InternalTransportCertificateThumbprint)"
            if ($after -eq $before) { Write-Log "${s}: internal transport certificate unchanged ($after)." OK }
            elseif ($replaceInternal) { Write-Log "${s}: internal transport certificate replaced: $before -> $after (as requested)." WARN }
            elseif ($before) {
                Invoke-Step "Set-TransportService -Identity $s -InternalTransportCertificateThumbprint $before   # restore" {
                    Set-TransportService -Identity $s -InternalTransportCertificateThumbprint $before -ErrorAction Stop
                }
                $now = "$((Get-TransportService -Identity $s).InternalTransportCertificateThumbprint)"
                if ($now -eq $before) { Write-Log "${s}: internal transport certificate restored to $before." OK }
                else { Write-Log "${s}: internal transport certificate is $now, expected $before - check manually." ERROR }
            }
            $c = Get-ExchangeCertSafe -Server $s -Thumbprint $thumb
            Write-Log "${s}: new certificate services now: $((Get-ServiceList $c) -join ',')" OK
        }
        catch { Write-Log "${s}: enable FAILED: $($_.Exception.Message)" ERROR }
    }
    if (-not (Test-DryRun)) {
        Update-Inventory
        Write-Log 'Next: run tab 4 (Verify). Connectors pinned to the old certificate (see tab 2 report) must be updated manually.' INFO
    }
}

# ---------------------------------------------------------------------------------------------
# Step 4: verify
# ---------------------------------------------------------------------------------------------
function Invoke-Verify {
    Assert-Exchange; Assert-Validated
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    $thumb = $script:State.NewThumb
    $sni = @($script:State.NewNames | Where-Object { $_ -notmatch '\*' } | Select-Object -First 1)[0]
    if (-not $sni) { $sni = ($script:State.NewNames | Select-Object -First 1) -replace '^\*\.', 'mail.' }
    $rows = New-Object System.Collections.Generic.List[object]
    $addRow = { param($srv, $check, $result, $detail) $rows.Add([pscustomobject]@{ Server = $srv; Check = $check; Result = $result; Detail = $detail }); Write-Log ("{0}: {1} = {2} - {3}" -f $srv, $check, $result, $detail) $(if ($result -eq 'FAIL') { 'ERROR' } elseif ($result -eq 'PASS') { 'OK' } else { 'INFO' }) }

    foreach ($s in $servers) {
        $fqdn = $script:State.Servers[$s].Fqdn
        $exOk = $false; $httpsOk = $false

        $c = Get-ExchangeCertSafe -Server $s -Thumbprint $thumb
        if (-not $c) { & $addRow $s 'Exchange: certificate present' 'FAIL' 'Not imported on this server' }
        else {
            $svc = Get-ServiceList $c
            $exOk = ($svc -contains 'IIS') -and ($svc -contains 'SMTP')
            & $addRow $s 'Exchange: services' $(if ($exOk) { 'PASS' } else { 'FAIL' }) ("Services = {0}" -f ($svc -join ','))
        }

        try {
            $r = Get-RemoteTlsCertificate -HostName $fqdn -Port 443 -SniName $sni
            $httpsOk = ($r.Thumbprint -eq $thumb)
            $detail = "Served $($r.Thumbprint) ($($r.Subject), exp $($r.NotAfter.ToString('yyyy-MM-dd')), $($r.Protocol))"
            if (-not $httpsOk) { $detail += ' - IIS still serves another certificate. Check the Default Web Site 443 binding; if correct, run "iisreset /noforce" on the server in a quiet period.' }
            & $addRow $s "HTTPS ${fqdn}:443" $(if ($httpsOk) { 'PASS' } else { 'FAIL' }) $detail
        }
        catch { & $addRow $s "HTTPS ${fqdn}:443" 'FAIL' $_.Exception.Message }

        try {
            $r = Get-RemoteTlsCertificate -HostName $fqdn -Port 25 -SniName $fqdn -StartTls
            if ($r.Thumbprint -eq $thumb) { & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'PASS' "Served new certificate ($($r.Protocol))" }
            else {
                & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'INFO' ("Served $($r.Thumbprint) ($($r.Subject)). Normal when the receive connector FQDN is the server's own name (Exchange then picks the certificate matching that name). Internet SMTP uses the name on your public MX connector.")
            }
        }
        catch { & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'INFO' "Could not probe: $($_.Exception.Message)" }

        try {
            $it = "$((Get-TransportService -Identity $s).InternalTransportCertificateThumbprint)"
            & $addRow $s 'Internal transport cert' 'INFO' $(if ($it -eq $thumb) { "Now the NEW certificate ($it)" } else { "Unchanged: $it" })
        }
        catch { & $addRow $s 'Internal transport cert' 'INFO' $_.Exception.Message }

        $script:State.Verified[$s] = ($exOk -and $httpsOk)
    }

    $extra = @($script:ui.ExtraEndpointsBox.Text -split '[,;\s]+' | Where-Object { $_ })
    foreach ($ep in $extra) {
        $h = $ep; $p = 443
        if ($ep -match '^(.+):(\d+)$') { $h = $Matches[1]; $p = [int]$Matches[2] }
        try {
            $r = Get-RemoteTlsCertificate -HostName $h -Port $p -SniName $h
            $ok = ($r.Thumbprint -eq $thumb)
            & $addRow '(endpoint)' "TLS ${h}:$p" $(if ($ok) { 'PASS' } else { 'INFO' }) ("Served $($r.Thumbprint) ($($r.Subject))" + $(if (-not $ok) { ' - if the load balancer terminates TLS, it needs the new certificate separately.' } else { '' }))
        }
        catch { & $addRow '(endpoint)' "TLS ${h}:$p" 'FAIL' $_.Exception.Message }
    }

    $script:ui.VerifyGrid.ItemsSource = (ConvertTo-DataTable $rows.ToArray() @('Server', 'Check', 'Result', 'Detail')).DefaultView
    $passed = @($servers | Where-Object { $script:State.Verified[$_] })
    Write-Log ("Verification: {0} of {1} server(s) passed (Exchange services + HTTPS)." -f $passed.Count, $servers.Count) $(if ($passed.Count -eq $servers.Count) { 'OK' } else { 'WARN' })
}

# ---------------------------------------------------------------------------------------------
# Step 5: remove old certificate
# ---------------------------------------------------------------------------------------------
function Update-OldCandidates {
    Assert-Exchange; Assert-Validated
    $servers = Get-SelectedServers
    Update-Inventory
    $cands = @($script:State.Inventory | Where-Object { $servers -contains $_.Server -and $_.SelfSigned -ne 'True' -and $_.Thumbprint -ne $script:State.NewThumb })
    $conns = @(Get-ConnectorTlsReport -Servers $servers -NewIssuer $script:State.NewCert.Issuer -NewSubject $script:State.NewCert.Subject -OldCerts $cands)
    $rows = foreach ($c in $cands) {
        $blockers = @()
        if (-not $script:State.Verified[$c.Server]) { $blockers += 'server not verified on tab 4' }
        if ($c.Thumbprint -eq $script:State.AuthThumb) { $blockers += 'is the Auth certificate' }
        if ($c.Thumbprint -eq $script:State.Servers[$c.Server].InternalTransportThumb) { $blockers += 'is the internal transport certificate' }
        if ($c.Services -match 'IIS') { $blockers += 'still bound to IIS' }
        $pinned = @($conns | Where-Object { -not $_.MatchesNew -and ($_.OldThumbprints -split ',') -contains $c.Thumbprint })
        if ($pinned) { $blockers += ('pinned by connector(s): ' + (($pinned | ForEach-Object { $_.Identity }) -join '; ')) }
        [pscustomobject]@{
            Server = $c.Server; Thumbprint = $c.Thumbprint; Subject = $c.Subject; NotAfter = $c.NotAfter
            Services = $c.Services; Removable = $(if ($blockers) { 'NO' } else { 'yes' }); Blockers = $blockers -join '; '
        }
    }
    $script:ui.OldGrid.ItemsSource = (ConvertTo-DataTable @($rows) @('Server', 'Thumbprint', 'Subject', 'NotAfter', 'Services', 'Removable', 'Blockers')).DefaultView
    Write-Log ("Old-certificate candidates: {0} (non-self-signed, not the new certificate)." -f @($rows).Count)
}

function Invoke-RemoveOld {
    Assert-Exchange; Assert-Validated
    $sel = @($script:ui.OldGrid.SelectedItems)
    if (-not $sel) { throw 'Select one or more rows in the grid first.' }
    $targets = @(foreach ($rv in $sel) {
            [pscustomobject]@{ Server = "$($rv.Row['Server'])"; Thumbprint = "$($rv.Row['Thumbprint'])"; Subject = "$($rv.Row['Subject'])"; Blockers = "$($rv.Row['Blockers'])" }
        })
    $blocked = @($targets | Where-Object { $_.Blockers })
    foreach ($b in $blocked) { Write-Log "$($b.Server): $($b.Thumbprint) NOT removable - $($b.Blockers)" WARN }
    $targets = @($targets | Where-Object { -not $_.Blockers })
    if (-not $targets) { throw 'None of the selected certificates can be removed safely (see Blockers column).' }

    $list = ($targets | ForEach-Object { "  $($_.Server): $($_.Thumbprint)  $($_.Subject)" }) -join "`n"
    $msg = "PERMANENTLY remove these certificates (including private keys) from the servers?`n`n$list`n`nMake sure you still have the old PFX if you may need to roll back."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Remove old certificate')) { Write-Log 'Removal cancelled.' WARN; return }

    foreach ($t in $targets) {
        try {
            Invoke-Step "Remove-ExchangeCertificate -Server $($t.Server) -Thumbprint $($t.Thumbprint) -Confirm:`$false" {
                Remove-ExchangeCertificate -Server $t.Server -Thumbprint $t.Thumbprint -Confirm:$false -ErrorAction Stop
                if (Get-ExchangeCertSafe -Server $t.Server -Thumbprint $t.Thumbprint) { throw 'certificate still present after removal' }
                Write-Log "$($t.Server): removed $($t.Thumbprint)." OK
            }
        }
        catch { Write-Log "$($t.Server): removal of $($t.Thumbprint) FAILED: $($_.Exception.Message)" ERROR }
    }
    Update-OldCandidates
}

# ---------------------------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------------------------
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Exchange Certificate Swap" Height="860" Width="1200" WindowStartupLocation="CenterScreen">
  <Window.Resources>
    <Style TargetType="Button"><Setter Property="Padding" Value="12,5"/><Setter Property="Margin" Value="0,0,8,0"/></Style>
    <Style TargetType="DataGrid">
      <Setter Property="IsReadOnly" Value="True"/><Setter Property="AutoGenerateColumns" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/><Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/><Setter Property="Margin" Value="0,8,0,0"/>
    </Style>
  </Window.Resources>
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="6"/><RowDefinition Height="200"/>
    </Grid.RowDefinitions>
    <DockPanel Grid.Row="0" Margin="0,0,0,8">
      <CheckBox x:Name="DryRunCheck" DockPanel.Dock="Right" IsChecked="True" VerticalAlignment="Center" FontWeight="Bold"
                Content="Dry run (log commands only, change nothing)"/>
      <TextBlock x:Name="StatusText" FontSize="15" FontWeight="Bold" VerticalAlignment="Center" Text="Exchange Certificate Swap"/>
    </DockPanel>

    <TabControl Grid.Row="1">
      <TabItem Header="1. Servers &amp; inventory">
        <Grid Margin="8">
          <Grid.ColumnDefinitions><ColumnDefinition Width="230"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <DockPanel Grid.Column="0" Margin="0,0,10,0">
            <TextBlock DockPanel.Dock="Top" Text="Mailbox servers (multi-select):" Margin="0,0,0,4"/>
            <StackPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
              <Button x:Name="ReloadServersButton" Content="Reload server list" Margin="0,0,0,6"/>
              <Button x:Name="RefreshButton" Content="Refresh certificate inventory"/>
            </StackPanel>
            <ListBox x:Name="ServerList" SelectionMode="Multiple"/>
          </DockPanel>
          <DockPanel Grid.Column="1">
            <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Foreground="DimGray"
                       Text="Read-only. Role column: Auth = OAuth certificate, InternalTransport = default SMTP certificate, NEW = the validated PFX."/>
            <DataGrid x:Name="InventoryGrid"/>
          </DockPanel>
        </Grid>
      </TabItem>

      <TabItem Header="2. New certificate (PFX)">
        <Grid Margin="8">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Grid.ColumnDefinitions><ColumnDefinition Width="110"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <TextBlock Text="PFX file:" VerticalAlignment="Center"/>
          <TextBox x:Name="PfxPathBox" Grid.Column="1" Margin="4"/>
          <Button x:Name="BrowseButton" Grid.Column="2" Content="Browse..." Margin="4"/>
          <TextBlock Grid.Row="1" Text="PFX password:" VerticalAlignment="Center"/>
          <PasswordBox x:Name="PfxPasswordBox" Grid.Row="1" Grid.Column="1" Margin="4"/>
          <Button x:Name="ValidateButton" Grid.Row="2" Grid.Column="1" HorizontalAlignment="Left" Margin="4"
                  Content="Validate certificate against Exchange (read-only)"/>
          <TextBox x:Name="ValidationBox" Grid.Row="3" Grid.ColumnSpan="3" Margin="0,8,0,0" IsReadOnly="True" FontFamily="Consolas"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
        </Grid>
      </TabItem>

      <TabItem Header="3. Import &amp; enable">
        <StackPanel Margin="12">
          <TextBlock TextWrapping="Wrap" Text="Step A imports the validated PFX into every selected server (the same PFX on each server, so all get the identical certificate and private key). Step B enables it for IIS and SMTP. The Exchange Back End website (port 444) keeps its self-signed certificate. Nothing is removed here - the old certificate stays until tab 5."/>
          <CheckBox x:Name="ExportableCheck" Margin="0,14,0,0" Content="Mark private key as exportable on the servers (only if you need to export it from Exchange later)"/>
          <CheckBox x:Name="ReplaceInternalCheck" Margin="0,6,0,0" Content="Also replace the internal transport (default SMTP) certificate - normally leave unchecked"/>
          <StackPanel Orientation="Horizontal" Margin="0,18,0,0">
            <Button x:Name="ImportButton" Content="Step A: Import PFX to selected servers"/>
            <Button x:Name="EnableButton" Content="Step B: Enable for IIS + SMTP"/>
          </StackPanel>
          <TextBlock Margin="0,18,0,0" TextWrapping="Wrap" Foreground="DimGray"
                     Text="Recommended: run both steps once with 'Dry run' ticked and read the log, then untick 'Dry run' and run them for real. Connectors that pin the old certificate (listed on tab 2) are reported only - update them manually with the command shown."/>
        </StackPanel>
      </TabItem>

      <TabItem Header="4. Verify">
        <DockPanel Margin="8">
          <StackPanel DockPanel.Dock="Top">
            <TextBlock Text="Extra TLS endpoints to probe, e.g. load balancer / public name (host or host:port, comma-separated):"/>
            <DockPanel Margin="0,4,0,0">
              <Button x:Name="VerifyButton" DockPanel.Dock="Right" Margin="8,0,0,0" Content="Run verification (read-only)"/>
              <TextBox x:Name="ExtraEndpointsBox"/>
            </DockPanel>
          </StackPanel>
          <DataGrid x:Name="VerifyGrid"/>
        </DockPanel>
      </TabItem>

      <TabItem Header="5. Remove old certificate">
        <DockPanel Margin="8">
          <StackPanel DockPanel.Dock="Top">
            <TextBlock TextWrapping="Wrap" Text="Optional. Lists non-self-signed certificates other than the new one. A row is removable only when its server passed verification and the certificate is not the Auth or internal transport certificate, not bound to IIS and not pinned by a connector."/>
            <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
              <Button x:Name="LoadOldButton" Content="Load candidates"/>
              <Button x:Name="RemoveButton" Content="Remove selected..."/>
            </StackPanel>
          </StackPanel>
          <DataGrid x:Name="OldGrid" SelectionMode="Extended" SelectionUnit="FullRow"/>
        </DockPanel>
      </TabItem>
    </TabControl>

    <GridSplitter Grid.Row="2" HorizontalAlignment="Stretch" VerticalAlignment="Center" Height="4"/>
    <TextBox x:Name="LogBox" Grid.Row="3" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
             VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
  </Grid>
</Window>
'@

function New-MainWindow {
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $win = [Windows.Markup.XamlReader]::Load($reader)
    $ns = New-Object System.Xml.XmlNamespaceManager($xaml.NameTable)
    $ns.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    $map = @{}
    foreach ($n in $xaml.SelectNodes('//*[@x:Name]', $ns)) {
        $name = $n.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
        $map[$name] = $win.FindName($name)
    }
    $script:Window = $win
    $script:ui = $map
}

$script:ActionButtons = 'ReloadServersButton', 'RefreshButton', 'BrowseButton', 'ValidateButton', 'ImportButton', 'EnableButton', 'VerifyButton', 'LoadOldButton', 'RemoveButton'

function Invoke-UiAction {
    param([string]$Name, [scriptblock]$Body)
    $script:Window.Cursor = [System.Windows.Input.Cursors]::Wait
    foreach ($b in $script:ActionButtons) { $script:ui[$b].IsEnabled = $false }
    Update-Ui
    try { & $Body }
    catch {
        Write-Log "$Name failed: $($_.Exception.Message)" ERROR
        [void][System.Windows.MessageBox]::Show($script:Window, $_.Exception.Message, "$Name failed",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
    finally {
        foreach ($b in $script:ActionButtons) { $script:ui[$b].IsEnabled = $true }
        $script:Window.Cursor = $null
    }
}

function Update-ModeBanner {
    if (Test-DryRun) {
        $script:ui.StatusText.Text = 'Exchange Certificate Swap  -  DRY RUN (no changes)'
        $script:ui.StatusText.Foreground = [System.Windows.Media.Brushes]::DarkGreen
    }
    else {
        $script:ui.StatusText.Text = 'Exchange Certificate Swap  -  LIVE MODE (changes will be made)'
        $script:ui.StatusText.Foreground = [System.Windows.Media.Brushes]::Firebrick
    }
}

function Register-UiEvents {
    $ui = $script:ui
    $ui.DryRunCheck.Add_Checked({ Update-ModeBanner; Write-Log 'Dry run ON.' })
    $ui.DryRunCheck.Add_Unchecked({ Update-ModeBanner; Write-Log 'Dry run OFF - LIVE MODE.' WARN })
    $ui.ReloadServersButton.Add_Click({ Invoke-UiAction 'Reload servers' { Update-ServerList } })
    $ui.RefreshButton.Add_Click({ Invoke-UiAction 'Inventory' { Update-Inventory } })
    $ui.BrowseButton.Add_Click({
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Filter = 'Certificate (*.pfx;*.p12)|*.pfx;*.p12|All files (*.*)|*.*'
            if ($dlg.ShowDialog($script:Window)) { $script:ui.PfxPathBox.Text = $dlg.FileName }
        })
    $ui.PfxPathBox.Add_TextChanged({ Reset-Validation })
    $ui.PfxPasswordBox.Add_PasswordChanged({ Reset-Validation })
    $ui.ValidateButton.Add_Click({ Invoke-UiAction 'Validate' { Invoke-ValidatePfx } })
    $ui.ImportButton.Add_Click({ Invoke-UiAction 'Import' { Invoke-ImportCertificate } })
    $ui.EnableButton.Add_Click({ Invoke-UiAction 'Enable' { Invoke-EnableCertificate } })
    $ui.VerifyButton.Add_Click({ Invoke-UiAction 'Verify' { Invoke-Verify } })
    $ui.LoadOldButton.Add_Click({ Invoke-UiAction 'Load candidates' { Update-OldCandidates } })
    $ui.RemoveButton.Add_Click({ Invoke-UiAction 'Remove' { Invoke-RemoveOld } })
    $script:Window.Add_ContentRendered({
            if (Test-ExchangeAvailable) { Invoke-UiAction 'Load servers' { Update-ServerList; Update-Inventory } }
            else {
                Write-Log 'Exchange cmdlets not available - only PFX checks will work. Run on an Exchange server.' ERROR
                $script:ui.StatusText.Text = 'Exchange cmdlets NOT loaded - run on an Exchange server'
                $script:ui.StatusText.Foreground = [System.Windows.Media.Brushes]::Firebrick
            }
        })
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
if ($LoadOnly) {
    New-MainWindow
    Register-UiEvents
    return
}

Write-Log "Exchange Certificate Swap started by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME. Log: $script:LogFile"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Log 'Not running elevated - Exchange certificate cmdlets may fail. Use "Run as administrator".' WARN }

# Load Exchange cmdlets at script scope (dot-sourcing inside a function would hide them).
if (-not (Test-ExchangeAvailable)) {
    $remoteExchange = if ($env:ExchangeInstallPath) { Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1' } else { $null }
    if ($remoteExchange -and (Test-Path -LiteralPath $remoteExchange)) {
        Write-Log "Connecting Exchange Management Shell via $remoteExchange ..."
        $ErrorActionPreference = 'Continue'
        try { . $remoteExchange; Connect-ExchangeServer -auto -ClientApplication:ManagementShell | Out-Null }
        catch { Write-Log "Connect-ExchangeServer failed: $($_.Exception.Message)" WARN }
        $ErrorActionPreference = 'Stop'
    }
}
if (-not (Test-ExchangeAvailable)) {
    try { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop; Write-Log 'Loaded Exchange snap-in.' }
    catch { Write-Log "Exchange snap-in not available: $($_.Exception.Message)" WARN }
}
if (Test-ExchangeAvailable) { Write-Log 'Exchange cmdlets available.' OK }

New-MainWindow
$script:ui.LogBox.Text = (Get-Content -LiteralPath $script:LogFile -Raw)
Register-UiEvents
Update-ModeBanner
[void]$script:Window.ShowDialog()
Write-Log 'Tool closed.'
