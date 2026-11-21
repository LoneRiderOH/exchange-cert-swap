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
      1b. Free certificate    - optional: requests a certificate from Let's Encrypt, ZeroSSL, Google
                                Trust Services, SSL.com or Actalis (HTTP-01 or DNS-01) with the
                                Posh-ACME module and loads the resulting PFX into tab 2.
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
    StagingThumbs = @()     # certificates issued by a staging ACME server in this session
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

    if ($leaf.Issuer -match '\(STAGING\)|Fake LE|Pebble|\bTest\b|Staging' -or @($script:State.StagingThumbs) -contains $leaf.Thumbprint) {
        $errors.Add('This is a STAGING/test certificate - clients do not trust it. Request it again from a production provider.')
    }
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
# Free ACME certificates (Let's Encrypt, ZeroSSL, Google, SSL.com, Actalis) via Posh-ACME - tab "1b"
# ---------------------------------------------------------------------------------------------
$script:Le = @{
    Mode       = $null      # 'HTTP' | 'DNSManual' | 'DNSPlugin'
    Plugin     = $null
    PluginArgs = $null
    Challenges = @()        # pending challenge objects (see New-LeChallenge)
    Names      = @()
}
$script:LeHttpPort = 80
$script:LeDnsResolvers = @('1.1.1.1', '8.8.8.8')
$script:LeWebConfig = @'
<?xml version="1.0" encoding="UTF-8"?>
<!-- Created by ExchangeCertTool for ACME HTTP-01 validation. Safe to delete. -->
<configuration>
  <system.webServer>
    <httpRedirect enabled="false" />
    <staticContent>
      <clear />
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
    <handlers>
      <clear />
      <add name="StaticFile" path="*" verb="GET,HEAD" modules="StaticFileModule" resourceType="Either" requireAccess="Read" />
    </handlers>
  </system.webServer>
</configuration>
'@

# Folders searched for Posh-ACME in addition to $env:PSModulePath. Windows PowerShell 5.1 does not see
# modules installed from PowerShell 7 (Documents\PowerShell\Modules), and a user-level PSModulePath
# environment variable or redirected Documents folder can hide the normal CurrentUser path.
function Get-PoshAcmeSearchRoots {
    $docs = @([Environment]::GetFolderPath('MyDocuments'), (Join-Path $env:USERPROFILE 'Documents'))
    if ($env:OneDrive) { $docs += (Join-Path $env:OneDrive 'Documents') }
    $roots = @(Join-Path $PSScriptRoot 'Modules')   # portable copy: Save-Module Posh-ACME -Path .\Modules
    foreach ($d in ($docs | Where-Object { $_ } | Select-Object -Unique)) {
        $roots += (Join-Path $d 'WindowsPowerShell\Modules')
        $roots += (Join-Path $d 'PowerShell\Modules')
    }
    $roots += (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
    $roots += (Join-Path $env:ProgramFiles 'PowerShell\Modules')
    $roots += @($env:PSModulePath -split ';' | Where-Object { $_ })
    @($roots | Where-Object { $_ } | Select-Object -Unique)
}

# Returns the path of the newest Posh-ACME.psd1 found, or $null.
function Find-PoshAcmeManifest {
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($root in Get-PoshAcmeSearchRoots) {
        $dir = Join-Path $root 'Posh-ACME'
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        foreach ($psd in @(Get-ChildItem -LiteralPath $dir -Filter 'Posh-ACME.psd1' -Recurse -Depth 1 -File -ErrorAction SilentlyContinue)) {
            $ver = [version]'0.0'
            try { $ver = [version](Import-PowerShellDataFile -LiteralPath $psd.FullName).ModuleVersion } catch { }
            $found.Add([pscustomobject]@{ Path = $psd.FullName; Version = $ver })
        }
    }
    $best = $found | Sort-Object Version -Descending | Select-Object -First 1
    if ($best) { return $best.Path }
    return $null
}

function Test-PoshAcme { [bool](Get-Command New-PAOrder -ErrorAction SilentlyContinue) -or [bool](Find-PoshAcmeManifest) }

function Write-PoshAcmeDiagnostics {
    Write-Log "Posh-ACME not found for $env:USERDOMAIN\$env:USERNAME (PowerShell $($PSVersionTable.PSVersion), $([IntPtr]::Size * 8)-bit). Searched:" WARN
    foreach ($r in Get-PoshAcmeSearchRoots) { Write-Log ("    {0}  {1}" -f $(if (Test-Path -LiteralPath $r) { '[exists] ' } else { '[missing]' }), $r) }
    Write-Log 'Install it in WINDOWS PowerShell (powershell.exe, not pwsh) as the same user that runs this tool: Install-Module Posh-ACME -Scope CurrentUser. Offline: Save-Module Posh-ACME -Path <tool folder>\Modules on another machine and copy the folder.' WARN
}

function Import-PoshAcme {
    if (Get-Command New-PAOrder -ErrorAction SilentlyContinue) { return }
    $psd = Find-PoshAcmeManifest
    if (-not $psd) {
        Write-PoshAcmeDiagnostics
        throw 'The Posh-ACME module was not found. Click "Install Posh-ACME" (see the log for the folders searched).'
    }
    try { Import-Module $psd -Force -ErrorAction Stop }
    catch {
        $policy = (Get-ExecutionPolicy -List | Where-Object { "$($_.ExecutionPolicy)" -ne 'Undefined' } | ForEach-Object { "$($_.Scope)=$($_.ExecutionPolicy)" }) -join ', '
        throw "Posh-ACME was found at $psd but could not be loaded: $($_.Exception.Message)  [Execution policy: $policy. If the files were copied from another machine, run: Get-ChildItem '$(Split-Path $psd)' -Recurse | Unblock-File]"
    }
    $onPath = [bool](Get-Module -ListAvailable -Name Posh-ACME)
    Write-Log "Loaded Posh-ACME $((Get-Module Posh-ACME).Version) from $psd$(if (-not $onPath) { ' (not on PSModulePath - loaded by full path)' })."
}

function Update-LeModuleStatus {
    if (-not (Test-PoshAcme)) {
        $script:ui.LeModuleText.Text = 'Posh-ACME: NOT found (needed for free ACME certificates). See the log for the folders searched.'
        $script:ui.LeModuleText.Foreground = [System.Windows.Media.Brushes]::Firebrick
        Write-PoshAcmeDiagnostics
        return
    }
    try {
        Import-PoshAcme
        $v = (Get-Module Posh-ACME).Version
        $script:ui.LeModuleText.Text = "Posh-ACME: installed$(if ($v) { " ($v)" })."
        $script:ui.LeModuleText.ToolTip = (Get-Module Posh-ACME).ModuleBase
        $script:ui.LeModuleText.Foreground = [System.Windows.Media.Brushes]::DarkGreen
        $current = $script:ui.LePluginCombo.Text
        $script:ui.LePluginCombo.Items.Clear()
        foreach ($p in @(Get-PAPlugin | Where-Object { "$($_.ChallengeType)" -eq 'dns-01' -and $_.Name -ne 'Manual' } | Sort-Object Name)) {
            [void]$script:ui.LePluginCombo.Items.Add("$($p.Name)")
        }
        if ($current) { $script:ui.LePluginCombo.Text = $current }
    }
    catch {
        $script:ui.LeModuleText.Text = 'Posh-ACME: found, but it could not be loaded - see the log.'
        $script:ui.LeModuleText.Foreground = [System.Windows.Media.Brushes]::Firebrick
        Write-Log "Posh-ACME check failed: $($_.Exception.Message)" ERROR
    }
}

function Install-PoshAcme {
    $existing = Find-PoshAcmeManifest
    if ($existing) { Write-Log "Posh-ACME is already installed: $existing" OK; Update-LeModuleStatus; return }
    $msg = "Install the Posh-ACME module from the PowerShell Gallery for the current user ($env:USERNAME) on $env:COMPUTERNAME?`n`nNeeds internet access to www.powershellgallery.com."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Install Posh-ACME')) { Write-Log 'Install cancelled.' WARN; return }
    Invoke-Step 'Install-Module Posh-ACME -Scope CurrentUser -Repository PSGallery' {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue |
            Where-Object { $_.Version -ge [version]'2.8.5.201' }
        if (-not $nuget) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null }
        Install-Module Posh-ACME -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
        $installed = @(Get-InstalledModule Posh-ACME -ErrorAction SilentlyContinue | Select-Object -First 1)
        Write-Log "Posh-ACME installed$(if ($installed) { ": $($installed[0].Version) in $($installed[0].InstalledLocation)" })." OK
    }
    Update-LeModuleStatus
}

function Get-LeMode {
    if ($script:ui.LeDnsManualRadio.IsChecked) { return 'DNSManual' }
    if ($script:ui.LeDnsPluginRadio.IsChecked) { return 'DNSPlugin' }
    return 'HTTP'
}

function Get-LeNames {
    $names = @($script:ui.LeNamesBox.Text -split '[\r\n,;\s]+' |
        ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $names) { throw 'Enter at least one name for the certificate.' }
    foreach ($n in $names) {
        if ($n -notmatch '^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$') { throw "Not a valid DNS name: $n" }
        if ($n -match '\.(local|lan|internal|corp|intra|localdomain|home|private)$') { throw "Public CAs cannot issue certificates for internal names: $n" }
    }
    if ($names.Count -gt 100) { throw "ACME certificates allow at most 100 names (you have $($names.Count))." }
    $names
}

function Resolve-PublicName {
    param([Parameter(Mandatory)][string]$Name, [string]$Type = 'A')
    foreach ($srv in $script:LeDnsResolvers) {
        try { return @(Resolve-DnsName -Name $Name -Type $Type -Server $srv -DnsOnly -QuickTimeout -ErrorAction Stop) }
        catch { }
    }
    return @()
}

function Get-LePublicAddress {
    param([string]$Name)
    $r = @(Resolve-PublicName -Name $Name -Type A)
    $ips = @($r | Where-Object { $_.Type -eq 'A' } | ForEach-Object { "$($_.IPAddress)" })
    $cname = @($r | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { "$($_.NameHost)" }) | Select-Object -First 1
    if (-not $ips) { return 'NOT in public DNS' }
    ($(if ($cname) { "CNAME $cname -> " } else { '' })) + ($ips -join ', ')
}

$script:LeInternalNamePattern = '\.(local|lan|internal|corp|intra|localdomain|home|private)$'

# The CA-issued certificate(s) currently bound to IIS on the selected servers, from the inventory.
function Get-CurrentIisCertificates {
    Assert-Exchange
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    if (-not $script:State.Inventory) { Update-Inventory }
    $rows = @($script:State.Inventory | Where-Object {
            $servers -contains $_.Server -and $_.SelfSigned -ne 'True' -and (($_.Services -split ',') -contains 'IIS') })
    foreach ($g in ($rows | Group-Object Thumbprint | Sort-Object @{ e = { $_.Count }; Descending = $true }, @{ e = { $_.Group[0].NotAfter }; Descending = $true })) {
        $r = $g.Group[0]
        [pscustomobject]@{
            Thumbprint = $r.Thumbprint; Subject = $r.Subject; NotAfter = $r.NotAfter; Issuer = $r.Issuer
            Servers    = @($g.Group | ForEach-Object { $_.Server })
            Domains    = @("$($r.Domains)" -split '\s*,\s*' | Where-Object { $_ })
        }
    }
}

function Set-LeNamesFromCurrentCert {
    param([switch]$Auto)
    $certs = @(Get-CurrentIisCertificates)
    if (-not $certs) {
        $m = 'No CA-issued certificate is bound to IIS on the selected servers (only self-signed).'
        if ($Auto) { Write-Log "$m Names not filled from a certificate." ; return $false }
        throw "$m Use ""Fill from Exchange URLs"" instead."
    }
    $names = New-Object System.Collections.Generic.List[string]
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($c in $certs) {
        $cn = if ("$($c.Subject)" -match '(?:^|,\s*)CN=([^,]+)') { $Matches[1].Trim() } else { $null }
        foreach ($n in @($cn) + $c.Domains) {
            if (-not $n) { continue }
            $n = $n.Trim().TrimEnd('.').ToLowerInvariant()
            if ($n -match $script:LeInternalNamePattern -or $n -notmatch '\.' -or $n -match '^[\d.]+$') { if (-not $skipped.Contains($n)) { $skipped.Add($n) }; continue }
            if (-not $names.Contains($n)) { $names.Add($n) }
        }
        Write-Log ("Current IIS certificate on {0}: {1} {2}, expires {3:yyyy-MM-dd}, issuer {4}" -f ($c.Servers -join ', '), $c.Thumbprint, $c.Subject, $c.NotAfter, $c.Issuer)
    }
    if ($certs.Count -gt 1) { Write-Log "The selected servers use $($certs.Count) different certificates - the names of all of them were combined." WARN }
    foreach ($s in $skipped) { Write-Log "Skipping $s (internal name or IP - public CAs cannot issue for it)." WARN }
    if (-not $names.Count) {
        if ($Auto) { Write-Log 'The current certificate has no public names usable for a public CA.' WARN; return $false }
        throw 'The current certificate has no public names usable for a public CA.'
    }
    $script:ui.LeNamesBox.Text = ($names -join "`r`n")
    if (($names -match '^\*') -and $script:ui.LeHttpRadio.IsChecked) {
        $script:ui.LeDnsManualRadio.IsChecked = $true
        Write-Log 'The current certificate contains a wildcard name - switched the challenge type to DNS-01 (HTTP-01 cannot validate wildcards).' WARN
    }
    Write-Log "Filled $($names.Count) name(s) from the current certificate. Review the list before requesting." OK
    return $true
}

# Called after the inventory loads: fill the names only if the box is still empty.
function Invoke-LeAutoFill {
    if ($script:ui.LeNamesBox.Text.Trim()) { return }
    try {
        if (Set-LeNamesFromCurrentCert -Auto) { return }
        Set-LeNamesFromExchange
    }
    catch { Write-Log "Could not pre-fill certificate names: $($_.Exception.Message)" WARN }
}

function Set-LeNamesFromExchange {
    Assert-Exchange
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    $hosts = New-Object System.Collections.Generic.List[string]
    foreach ($h in @(Get-ExchangeHostNames -Servers $servers | Select-Object -ExpandProperty Host -Unique)) {
        if ($h -match $script:LeInternalNamePattern -or $h -notmatch '\.') {
            Write-Log "Skipping internal name $h (public CAs cannot issue for it)." WARN; continue
        }
        if (-not $hosts.Contains($h)) { $hosts.Add($h) }
    }
    try {
        foreach ($d in @(Get-AcceptedDomain)) {
            $ad = "autodiscover.$($d.DomainName)".ToLowerInvariant()
            if ($ad -match '\*' -or $hosts.Contains($ad)) { continue }
            if (@(Resolve-PublicName -Name $ad -Type A | Where-Object { $_.Type -in 'A', 'CNAME' }).Count) { $hosts.Add($ad) }
            else { Write-Log "$ad has no public DNS record - not added." }
        }
    }
    catch { Write-Log "Get-AcceptedDomain failed: $($_.Exception.Message)" WARN }
    if (-not $hosts.Count) { throw 'No public host names found on the Exchange virtual directories.' }
    $script:ui.LeNamesBox.Text = ($hosts -join "`r`n")
    foreach ($h in $hosts) { Write-Log ("  {0,-35} public DNS: {1}" -f $h, (Get-LePublicAddress $h)) }
    Write-Log "Filled $($hosts.Count) name(s) from Exchange URLs. Review the list before requesting." OK
}

function ConvertFrom-LePluginArgs {
    param([string]$Text)
    $h = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        if ($l -notmatch '^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$') { throw "Plugin argument lines must look like Name=Value (problem: '$($l.Split('=')[0])')." }
        $n = $Matches[1]; $v = $Matches[2].Trim()
        if ($v -match '^secure:(.*)$') { $h[$n] = ConvertTo-SecureString $Matches[1] -AsPlainText -Force }
        elseif ($v -match '^(?i:true|false)$') { $h[$n] = [bool]::Parse($v) }
        elseif ($v -match '^\[(.*)\]$') { $h[$n] = @($Matches[1] -split '\s*,\s*' | Where-Object { $_ }) }
        else { $h[$n] = $v }
    }
    $h
}

function Get-LeWebroots {
    $template = $script:ui.LeWebrootBox.Text.Trim()
    if (-not $template) { throw 'Enter the webroot path for HTTP-01.' }
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select the servers on tab 1. The challenge file goes to every selected server, because a load balancer can send the CA''s validation request to any of them.' }
    foreach ($s in $servers) {
        $fqdn = if ($script:State.Servers.ContainsKey($s) -and $script:State.Servers[$s].Fqdn) { $script:State.Servers[$s].Fqdn } else { $s }
        [pscustomobject]@{ Server = $s; Fqdn = $fqdn; Root = (($template -replace '\{server\}', $s) -replace '\{fqdn\}', $fqdn) }
    }
}

function Write-LeChallengeFile {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Content)
    if (-not (Test-Path -LiteralPath $Root)) { throw "Webroot not reachable: $Root" }
    $dir = Join-Path $Root '.well-known\acme-challenge'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $wc = Join-Path $dir 'web.config'
    if (-not (Test-Path -LiteralPath $wc)) { [IO.File]::WriteAllText($wc, $script:LeWebConfig, $utf8) }
    $file = Join-Path $dir $Token
    [IO.File]::WriteAllText($file, $Content, $utf8)
    $file
}

function Invoke-LeHttpProbe {
    param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][string]$HostHeader, [Parameter(Mandatory)][string]$Token)
    $url = 'http://{0}:{1}/.well-known/acme-challenge/{2}' -f $Target, $script:LeHttpPort, $Token
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Host = $HostHeader
    $req.AllowAutoRedirect = $false
    $req.Timeout = 10000
    $req.Proxy = $null
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch {
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
        if ($ex -and $ex.Response) { $resp = $ex.Response }
        else { return [pscustomobject]@{ Ok = $false; Status = 'no response'; Body = ''; Detail = $_.Exception.Message } }
    }
    try {
        $code = [int]$resp.StatusCode
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd(); $sr.Close()
        $loc = $resp.Headers['Location']
        [pscustomobject]@{ Ok = ($code -eq 200); Status = $code; Body = $body.Trim(); Detail = $(if ($loc) { "redirects to $loc" } else { '' }) }
    }
    finally { $resp.Close() }
}

function Get-LeProbeHint {
    param($Probe)
    if ($Probe.Ok) { return '' }
    switch -Regex ("$($Probe.Status)") {
        '^30\d' { return 'IIS redirects this path; CAs follow redirects only to the same name on 80/443. Check HTTP Redirect on Default Web Site.' }
        '^403' { return '"Require SSL" is probably set on Default Web Site - HTTP-01 needs plain HTTP on port 80.' }
        '^404' { return 'File not served - is the webroot path the physical path of Default Web Site?' }
        'no response' { return 'Port 80 not reachable from here (firewall, or IIS not listening on 80).' }
        default { return '' }
    }
}

function New-LeChallenge {
    param($Auth, [string]$Type)
    [pscustomobject]@{
        Fqdn      = "$($Auth.fqdn)"
        DnsId     = "$($Auth.DNSId)"
        Type      = $Type
        Token     = $(if ($Type -eq 'http-01') { "$($Auth.HTTP01Token)" } else { "$($Auth.DNS01Token)" })
        Url       = $(if ($Type -eq 'http-01') { "$($Auth.HTTP01Url)" } else { "$($Auth.DNS01Url)" })
        Record    = ''
        Value     = ''
        Files     = New-Object System.Collections.Generic.List[string]
        Published = $false
        Status    = 'pending'
    }
}

function Show-LeChallenges {
    $rows = foreach ($c in $script:Le.Challenges) {
        [pscustomobject]@{
            Name   = $c.Fqdn
            Type   = $c.Type
            Record = $(if ($c.Type -eq 'dns-01') { "$($c.Record)  (TXT)" } else { "http://$($c.DnsId)/.well-known/acme-challenge/$($c.Token)" })
            Value  = $c.Value
            Status = $c.Status
        }
    }
    $script:ui.LeGrid.ItemsSource = (ConvertTo-DataTable @($rows) @('Name', 'Type', 'Record', 'Value', 'Status')).DefaultView
    Update-Ui
}

function Wait-Ui {
    param([double]$Seconds)
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) { Update-Ui; Start-Sleep -Milliseconds 200 }
}

function Test-LeHttpSetup {
    $names = @(Get-LeNames | Where-Object { $_ -notmatch '^\*' })
    if (-not $names) { throw 'Only wildcard names entered - HTTP-01 cannot be used for wildcards.' }
    $roots = @(Get-LeWebroots)
    $token = 'certtool-test-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $content = 'ok-' + [guid]::NewGuid().ToString('N')
    if (Test-DryRun) {
        foreach ($r in $roots) { Write-Log "[DRY RUN] would write test file $($r.Root)\.well-known\acme-challenge\$token and request it via http://$($r.Fqdn)/ for each name" CMD }
        Write-Log 'Untick Dry run to actually run the HTTP-01 test (it writes and then deletes a small text file).' INFO
        return
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $files = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($r in $roots) {
            try { $files.Add((Write-LeChallengeFile -Root $r.Root -Token $token -Content $content)); Write-Log "$($r.Server): wrote test file to $($r.Root)" }
            catch { $rows.Add([pscustomobject]@{ Name = $r.Server; Type = 'write'; Record = $r.Root; Value = ''; Status = "FAIL: $($_.Exception.Message)" }) }
        }
        foreach ($r in $roots) {
            foreach ($n in $names) {
                $p = Invoke-LeHttpProbe -Target $r.Fqdn -HostHeader $n -Token $token
                $ok = $p.Ok -and $p.Body -eq $content
                $status = if ($ok) { 'PASS' } else { "FAIL ($($p.Status)) $($p.Detail) $(Get-LeProbeHint $p)".Trim() }
                $rows.Add([pscustomobject]@{ Name = $n; Type = "via $($r.Server)"; Record = "http://$($r.Fqdn)/.well-known/acme-challenge/ (Host: $n)"; Value = ''; Status = $status })
                Write-Log ("HTTP-01 test {0} via {1}: {2}" -f $n, $r.Server, $status) $(if ($ok) { 'OK' } else { 'WARN' })
            }
        }
        foreach ($n in $names) {
            $pub = Get-LePublicAddress $n
            $rows.Add([pscustomobject]@{ Name = $n; Type = 'public DNS'; Record = $pub; Value = ''; Status = $(if ($pub -like 'NOT*') { 'FAIL - name must resolve publicly' } else { 'INFO - port 80 on this address must reach the Exchange servers' }) })
        }
    }
    finally {
        foreach ($f in $files) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        if ($files.Count) { Write-Log "Removed $($files.Count) test file(s)." }
    }
    $script:ui.LeGrid.ItemsSource = (ConvertTo-DataTable $rows.ToArray() @('Name', 'Type', 'Record', 'Value', 'Status')).DefaultView
    $script:ui.LeStatusText.Text = 'HTTP-01 test done. This checks IIS on each server from inside your network; it cannot prove that port 80 from the internet reaches Exchange (check your firewall / load balancer).'
}

# Free ACME certificate authorities supported by Posh-ACME (order = combo box order).
# EC-only endpoints (SSLCOM_ECC) are left out on purpose: Exchange needs RSA certificates.
$script:AcmeProviders = @(
    [pscustomobject]@{ Name = 'Let''s Encrypt'; Label = 'Let''s Encrypt - Staging (test, untrusted)'; Server = 'LE_STAGE'; Staging = $true; Eab = $false
        Help = 'No account needed. Use Staging first to prove the challenge works.'; Limits = '' }
    [pscustomobject]@{ Name = 'Let''s Encrypt'; Label = 'Let''s Encrypt - Production'; Server = 'LE_PROD'; Staging = $false; Eab = $false
        Help = 'No account needed.'; Limits = 'Let''s Encrypt allows 5 certificates for the same set of names per week.' }
    [pscustomobject]@{ Name = 'ZeroSSL'; Label = 'ZeroSSL'; Server = 'ZEROSSL_PROD'; Staging = $false; Eab = $true
        Help = 'Needs EAB credentials (only for the first request). Click "Get from e-mail" to generate them from the contact e-mail, or copy them from app.zerossl.com > Developer > EAB Credentials.'; Limits = '' }
    [pscustomobject]@{ Name = 'Google Trust Services'; Label = 'Google Trust Services - Staging (test, untrusted)'; Server = 'GOOGLE_STAGE'; Staging = $true; Eab = $true
        Help = 'Needs a Google Cloud project. In Cloud Shell: gcloud services enable publicca.googleapis.com ; gcloud config set api_endpoint_overrides/publicca https://preprod-publicca.googleapis.com/ ; gcloud publicca external-account-keys create  -> keyId = EAB key ID, b64MacKey = HMAC key. Staging keys only work on staging. Use within 7 days.'; Limits = '' }
    [pscustomobject]@{ Name = 'Google Trust Services'; Label = 'Google Trust Services - Production'; Server = 'GOOGLE_PROD'; Staging = $false; Eab = $true
        Help = 'Needs a Google Cloud project. In Cloud Shell: gcloud services enable publicca.googleapis.com ; gcloud publicca external-account-keys create  -> keyId = EAB key ID, b64MacKey = HMAC key. Use within 7 days.'; Limits = '' }
    [pscustomobject]@{ Name = 'SSL.com'; Label = 'SSL.com (RSA)'; Server = 'SSLCOM_RSA'; Staging = $false; Eab = $true
        Help = 'Needs a free SSL.com account. Copy the ACME credentials (account key = EAB key ID, HMAC key) from your SSL.com dashboard.'; Limits = '' }
    [pscustomobject]@{ Name = 'Actalis'; Label = 'Actalis'; Server = 'ACTALIS_PROD'; Staging = $false; Eab = $true
        Help = 'Needs a free Actalis account with the free ACME certificate product. Copy the EAB KID and HMAC key from the Actalis dashboard.'; Limits = '' }
)

function Get-AcmeProvider {
    $i = 0
    if ($script:ui -and $script:ui.LeProviderCombo -and $script:ui.LeProviderCombo.SelectedIndex -ge 0) { $i = $script:ui.LeProviderCombo.SelectedIndex }
    $script:AcmeProviders[$i]
}

function Update-AcmeProviderUi {
    $pr = Get-AcmeProvider
    $script:ui.LeEabPanel.Visibility = if ($pr.Eab) { 'Visible' } else { 'Collapsed' }
    $script:ui.LeZeroSslEabButton.Visibility = if ($pr.Server -eq 'ZEROSSL_PROD') { 'Visible' } else { 'Collapsed' }
    $script:ui.LeProviderHelpText.Text = $pr.Help
    $script:ui.LeTosCheck.Content = "I accept the $($pr.Name) subscriber agreement / terms of service"
    $script:ui.LeTosCheck.IsChecked = $false
    $script:ui.LeEabKidBox.Text = ''
    $script:ui.LeEabHmacBox.Password = ''
}

function Get-ZeroSslEab {
    $email = $script:ui.LeEmailBox.Text.Trim()
    if ($email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw 'Enter a valid contact e-mail first - ZeroSSL ties the EAB credentials to it.' }
    $msg = "Ask ZeroSSL (api.zerossl.com) for EAB credentials for $email?`n`nThis registers the address with ZeroSSL if it is new."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - ZeroSSL is not contacted)" }
    if (-not (Confirm-Action $msg 'ZeroSSL EAB')) { Write-Log 'Cancelled.' WARN; return }
    if (Test-DryRun) { Write-Log "[DRY RUN] POST https://api.zerossl.com/acme/eab-credentials-email email=$email" CMD; return }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Log "POST https://api.zerossl.com/acme/eab-credentials-email email=$email" CMD
    $r = Invoke-RestMethod -Method Post -Uri 'https://api.zerossl.com/acme/eab-credentials-email' -Body @{ email = $email } -UseBasicParsing -TimeoutSec 30
    if (-not $r.success -or -not $r.eab_kid -or -not $r.eab_hmac_key) {
        throw "ZeroSSL did not return EAB credentials: $(($r | ConvertTo-Json -Compress -Depth 3) -replace '"eab_hmac_key":"[^"]*"', '"eab_hmac_key":"<hidden>"')"
    }
    $script:ui.LeEabKidBox.Text = "$($r.eab_kid)"
    $script:ui.LeEabHmacBox.Password = "$($r.eab_hmac_key)"
    Write-Log "ZeroSSL EAB credentials received (key ID $($r.eab_kid))." OK
}

function Start-LeRequest {
    $names = @(Get-LeNames)
    $mode = Get-LeMode
    if ($mode -eq 'HTTP' -and ($names -match '^\*')) { throw 'Wildcard names need DNS-01. Choose a DNS-01 option or remove the wildcard.' }
    $provider = Get-AcmeProvider
    if (-not $script:ui.LeTosCheck.IsChecked) { throw "Tick ""I accept the $($provider.Name) subscriber agreement"" first." }
    if ($script:Le.Challenges.Count) { throw 'A previous request still has challenges in place. Click "Continue" or "Clean up challenges" first.' }
    $email = $script:ui.LeEmailBox.Text.Trim()
    if ($email -and $email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Not a valid e-mail address: $email" }
    $prod = -not $provider.Staging
    $acmeServer = $provider.Server
    $eabKid = $script:ui.LeEabKidBox.Text.Trim()
    $eabHmac = $script:ui.LeEabHmacBox.Password.Trim()
    if ($provider.Eab -and [bool]$eabKid -ne [bool]$eabHmac) { throw 'Enter both the EAB key ID and the EAB HMAC key (or neither, if an ACME account for this provider already exists).' }
    $keyLen = "$($script:ui.LeKeyCombo.SelectedItem.Content)"
    $plugin = $null; $pluginArgs = $null; $roots = @()
    if ($mode -eq 'DNSPlugin') {
        $plugin = $script:ui.LePluginCombo.Text.Trim()
        if (-not $plugin) { throw 'Choose a DNS plugin (e.g. Cloudflare, Route53, Azure).' }
        $pluginArgs = ConvertFrom-LePluginArgs $script:ui.LePluginArgsBox.Text
    }
    if ($mode -eq 'HTTP') { $roots = @(Get-LeWebroots) }

    $modeText = @{ HTTP = 'HTTP-01 (file in IIS)'; DNSManual = 'DNS-01 (you add TXT records)'; DNSPlugin = "DNS-01 via plugin $plugin" }[$mode]
    $msg = "Request a certificate from $($provider.Label)`n`n" +
    "Names:`n  $($names -join "`n  ")`n`nChallenge: $modeText`nKey: RSA $keyLen"
    if ($mode -eq 'HTTP') { $msg += "`n`nChallenge files will be written to:`n  $(($roots | ForEach-Object { $_.Root }) -join "`n  ")" }
    if ($provider.Limits) { $msg += "`n`n$($provider.Limits) Test with a staging provider first." }
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - $($provider.Name) is not contacted, nothing is written)" }
    if (-not (Confirm-Action $msg "$($provider.Name) request")) { Write-Log 'Request cancelled.' WARN; return }

    if (Test-DryRun) {
        Write-Log "[DRY RUN] Set-PAServer $acmeServer" CMD
        Write-Log "[DRY RUN] New-PAAccount -AcceptTOS$(if ($email) { " -Contact $email" })$(if ($eabKid) { " -ExtAcctKID $eabKid -ExtAcctHMACKey <hidden>" }) (only if no account exists yet)" CMD
        Write-Log "[DRY RUN] New-PAOrder -Domain $($names -join ',') -KeyLength $keyLen -PfxPass <random> -Force" CMD
        switch ($mode) {
            'HTTP' { foreach ($r in $roots) { Write-Log "[DRY RUN] write <token> + web.config to $($r.Root)\.well-known\acme-challenge\" CMD } }
            'DNSManual' { Write-Log '[DRY RUN] show _acme-challenge TXT records for you to create, then wait for "Continue"' CMD }
            'DNSPlugin' { Write-Log "[DRY RUN] Publish-Challenge/Save-Challenge -Plugin $plugin -PluginArgs <$(@($pluginArgs.Keys) -join ', ')>" CMD }
        }
        Write-Log '[DRY RUN] Send-ChallengeAck, wait for validation, Submit-OrderFinalize, Complete-PAOrder, remove challenges, load fullchain.pfx into tab 2' CMD
        return
    }

    Import-PoshAcme
    Write-Log "Set-PAServer $acmeServer" CMD
    Set-PAServer $acmeServer
    $acct = Get-PAAccount
    if (-not $acct -or "$($acct.status)" -ne 'valid') {
        if ($provider.Eab -and -not $eabKid) {
            throw "$($provider.Name) needs EAB credentials to create the ACME account on this server. $($provider.Help)"
        }
        Write-Log "New-PAAccount -AcceptTOS$(if ($email) { " -Contact $email" })$(if ($eabKid) { " -ExtAcctKID $eabKid -ExtAcctHMACKey <hidden>" })" CMD
        $acctArgs = @{ AcceptTOS = $true; Force = $true }
        if ($email) { $acctArgs.Contact = $email }
        if ($eabKid) { $acctArgs.ExtAcctKID = $eabKid; $acctArgs.ExtAcctHMACKey = $eabHmac }
        $acct = New-PAAccount @acctArgs
    }
    elseif ($eabKid) { Write-Log "An ACME account for $($provider.Name) already exists ($($acct.id)) - the EAB credentials were not needed." }
    Write-Log "ACME account: $($acct.id) ($acmeServer)"

    Write-Log "New-PAOrder -Domain $($names -join ',') -KeyLength $keyLen -PfxPass <random> -Force" CMD
    $order = New-PAOrder -Domain $names -KeyLength $keyLen -PfxPassSecure (New-RandomSecurePassword) -FriendlyName ("Exchange {0} {1:yyyy-MM-dd}" -f $names[0], (Get-Date)) -Force
    Write-Log "Order $($order.Name) created, status $($order.status)."

    $script:Le.Provider = $provider
    $script:Le.Mode = $mode; $script:Le.Plugin = $plugin; $script:Le.PluginArgs = $pluginArgs; $script:Le.Names = $names
    $challenges = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($a in @($order | Get-PAAuthorization)) {
            if ("$($a.status)" -eq 'valid') { Write-Log "$($a.fqdn): already authorized (reused)." OK; continue }
            if ("$($a.status)" -ne 'pending') { throw "Authorization for $($a.fqdn) is '$($a.status)'." }
            if ($mode -eq 'HTTP') {
                if (-not $a.HTTP01Token) { throw "The CA offered no HTTP-01 challenge for $($a.fqdn)." }
                $c = New-LeChallenge $a 'http-01'
                $c.Value = Get-KeyAuthorization $c.Token
                foreach ($r in $roots) {
                    $c.Files.Add((Write-LeChallengeFile -Root $r.Root -Token $c.Token -Content $c.Value))
                    Write-Log "$($c.Fqdn): challenge file written on $($r.Server)."
                }
                foreach ($r in $roots) {
                    $p = Invoke-LeHttpProbe -Target $r.Fqdn -HostHeader $c.DnsId -Token $c.Token
                    if ($p.Ok -and $p.Body -eq $c.Value) { Write-Log "$($c.Fqdn): served correctly by $($r.Server)." OK }
                    else { Write-Log "$($c.Fqdn): NOT served correctly by $($r.Server) ($($p.Status) $($p.Detail)). $(Get-LeProbeHint $p)" WARN }
                }
            }
            else {
                if (-not $a.DNS01Token) { throw "The CA offered no DNS-01 challenge for $($a.fqdn)." }
                $c = New-LeChallenge $a 'dns-01'
                $c.Record = "_acme-challenge.$($c.DnsId)"
                $c.Value = Get-KeyAuthorization $c.Token -ForDNS
                if ($mode -eq 'DNSPlugin') {
                    Write-Log "Publish-Challenge $($c.DnsId) -Plugin $plugin" CMD
                    Publish-Challenge -Domain $c.DnsId -Account $acct -Token $c.Token -Plugin $plugin -PluginArgs $pluginArgs
                    $c.Published = $true
                }
            }
            $challenges.Add($c)
        }
        $script:Le.Challenges = $challenges.ToArray()
        if ($mode -eq 'DNSPlugin' -and $challenges.Count) {
            Write-Log "Save-Challenge -Plugin $plugin" CMD
            Save-Challenge -Plugin $plugin -PluginArgs $pluginArgs
        }
    }
    catch {
        $script:Le.Challenges = $challenges.ToArray()
        Clear-LeChallenges
        throw
    }
    Show-LeChallenges

    if ($mode -eq 'DNSManual' -and $challenges.Count) {
        $script:ui.LeStatusText.Text = 'Create these TXT records in your public DNS zone (one record per row; the same name can have two values). Then click "Check DNS records" and "Continue (records added)".'
        Write-Log 'Waiting for you to add the TXT records shown in the grid, then click "Continue (records added)".' WARN
        foreach ($c in $challenges) { Write-Log ("  TXT  {0}  =  {1}" -f $c.Record, $c.Value) }
        return
    }
    Complete-LeRequest
}

function New-RandomSecurePassword {
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ConvertTo-SecureString ([Convert]::ToBase64String($bytes) -replace '[+/=]', 'x') -AsPlainText -Force
}

function Test-LeDnsRecords {
    param([switch]$Quiet)
    $dns = @($script:Le.Challenges | Where-Object { $_.Type -eq 'dns-01' })
    if (-not $dns) { if (-not $Quiet) { throw 'No pending DNS-01 challenges.' } return $true }
    $all = $true
    foreach ($c in $dns) {
        $found = @()
        foreach ($srv in $script:LeDnsResolvers) {
            try { $found += @(Resolve-DnsName -Name $c.Record -Type TXT -Server $srv -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { $_.Strings -join '' }) }
            catch { }
        }
        $ok = $found -contains $c.Value
        $c.Status = if ($ok) { 'TXT visible' } elseif ($found) { 'TXT found, wrong value' } else { 'TXT not visible yet' }
        if (-not $ok) { $all = $false }
        if (-not $Quiet) { Write-Log ("{0}: {1}" -f $c.Record, $c.Status) $(if ($ok) { 'OK' } else { 'WARN' }) }
    }
    Show-LeChallenges
    return $all
}

function Complete-LeRequest {
    Import-PoshAcme
    $order = Get-PAOrder -Refresh
    if (-not $order) { throw 'No current Posh-ACME order. Click "Request certificate" first.' }
    $pending = @($script:Le.Challenges)
    if (-not $pending -and "$($order.status)" -eq 'pending') { throw 'No challenges are in place for the current order. Click "Request certificate" again.' }
    $keepChallenges = $false
    try {
        if ($pending | Where-Object { $_.Type -eq 'dns-01' }) {
            Write-Log 'Waiting for the TXT records to appear in public DNS (up to 5 minutes)...'
            $deadline = (Get-Date).AddMinutes(5)
            while (-not (Test-LeDnsRecords -Quiet)) {
                if ((Get-Date) -gt $deadline) {
                    if ($script:Le.Mode -eq 'DNSManual') { $keepChallenges = $true; throw 'TXT records are still not visible on public resolvers. Check them, then click "Continue" again.' }
                    Write-Log 'TXT records not visible on public resolvers yet - asking the CA to validate anyway.' WARN
                    break
                }
                Wait-Ui 10
            }
        }
        foreach ($c in $pending) {
            Write-Log "Send-ChallengeAck $($c.Fqdn) ($($c.Type))" CMD
            Send-ChallengeAck -ChallengeUrl $c.Url
            $c.Status = 'submitted'
        }
        Show-LeChallenges

        $deadline = (Get-Date).AddMinutes(3)
        while ($true) {
            $auths = @($order | Get-PAAuthorization)
            $bad = @($auths | Where-Object { "$($_.status)" -in 'invalid', 'deactivated', 'expired', 'revoked' })
            foreach ($c in $pending) {
                $a = $auths | Where-Object { "$($_.fqdn)" -eq $c.Fqdn } | Select-Object -First 1
                if ($a) { $c.Status = "$($a.status)" }
            }
            Show-LeChallenges
            if ($bad) {
                $details = foreach ($b in $bad) {
                    $err = @($b.challenges | Where-Object { $_.error } | ForEach-Object { $_.error.detail }) -join '; '
                    "$($b.fqdn): $($b.status) - $err"
                }
                throw "$($script:Le.Provider.Name) validation failed:`n$($details -join "`n")"
            }
            if (-not @($auths | Where-Object { "$($_.status)" -ne 'valid' })) { break }
            if ((Get-Date) -gt $deadline) { throw 'Timed out waiting for the CA to validate the challenges.' }
            Wait-Ui 3
        }
        Write-Log 'All names validated.' OK

        $order = Get-PAOrder -Refresh
        $deadline = (Get-Date).AddMinutes(2)
        while ("$($order.status)" -eq 'pending') {
            if ((Get-Date) -gt $deadline) { throw 'Order did not become ready.' }
            Wait-Ui 2; $order = Get-PAOrder -Refresh
        }
        if ("$($order.status)" -eq 'ready') {
            Write-Log 'Submit-OrderFinalize' CMD
            $order | Submit-OrderFinalize
        }
        $deadline = (Get-Date).AddMinutes(3)
        $order = Get-PAOrder -Refresh
        while ("$($order.status)" -ne 'valid') {
            if ("$($order.status)" -eq 'invalid') { throw 'Order became invalid during finalization.' }
            if ((Get-Date) -gt $deadline) { throw "Timed out waiting for the certificate (order status $($order.status))." }
            Wait-Ui 3; $order = Get-PAOrder -Refresh
        }
        Write-Log 'Complete-PAOrder' CMD
        $cert = $order | Complete-PAOrder
        if (-not $cert -or -not $cert.PfxFullChain -or -not (Test-Path -LiteralPath $cert.PfxFullChain)) { throw 'Certificate issued, but fullchain.pfx was not found.' }
        Write-Log ("Certificate issued by {3}: {0}, thumbprint {1}, expires {2:yyyy-MM-dd}." -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter, $script:Le.Provider.Label) OK
        if ($script:Le.Provider.Staging) { $script:State.StagingThumbs += "$($cert.Thumbprint)" }
        Write-Log "PFX: $($cert.PfxFullChain) (password kept by Posh-ACME: (Get-PAOrder '$($order.Name)').PfxPass)"
    }
    finally { if (-not $keepChallenges) { Clear-LeChallenges } }

    $script:ui.PfxPathBox.Text = $cert.PfxFullChain
    $script:ui.PfxPasswordBox.Password = (New-Object System.Net.NetworkCredential('', $cert.PfxPass)).Password
    $script:ui.LeStatusText.Text = "Certificate issued. It was loaded into tab 2 and validated - continue there."
    $script:ui.MainTabs.SelectedIndex = 2
    Update-Ui
    Invoke-ValidatePfx
}

function Clear-LeChallenges {
    $list = @($script:Le.Challenges)
    if (-not $list) { Write-Log 'No challenges to clean up.'; return }
    $published = $false
    foreach ($c in $list) {
        foreach ($f in $c.Files) {
            try { Remove-Item -LiteralPath $f -Force -ErrorAction Stop; Write-Log "Removed challenge file $f" }
            catch { Write-Log "Could not remove $f : $($_.Exception.Message)" WARN }
        }
        if ($c.Type -eq 'dns-01' -and $c.Published -and $script:Le.Plugin) {
            try {
                Unpublish-Challenge -Domain $c.DnsId -Account (Get-PAAccount) -Token $c.Token -Plugin $script:Le.Plugin -PluginArgs $script:Le.PluginArgs
                $published = $true
            }
            catch { Write-Log "Unpublish-Challenge $($c.DnsId) failed: $($_.Exception.Message)" WARN }
        }
        elseif ($c.Type -eq 'dns-01' -and $script:Le.Mode -eq 'DNSManual') {
            Write-Log "You can delete the TXT record $($c.Record) = $($c.Value) now." INFO
        }
    }
    if ($published) {
        try { Save-Challenge -Plugin $script:Le.Plugin -PluginArgs $script:Le.PluginArgs; Write-Log 'DNS challenge records removed via plugin.' OK }
        catch { Write-Log "Save-Challenge (cleanup) failed: $($_.Exception.Message)" WARN }
    }
    $script:Le.Challenges = @()
}

function Show-LePluginParams {
    Import-PoshAcme
    $p = $script:ui.LePluginCombo.Text.Trim()
    if (-not $p) { throw 'Choose a plugin first.' }
    Write-Log "Parameters for plugin ${p}:"
    foreach ($l in ((Get-PAPlugin -Plugin $p -Params | Out-String -Width 200) -split "`r?`n")) { if ($l.Trim()) { Write-Log "  $l" } }
    Write-Log "Full guide: Get-PAPlugin $p -Guide   (https://poshac.me/docs/latest/Plugins/$p/)"
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

    <TabControl x:Name="MainTabs" Grid.Row="1">
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

      <TabItem Header="1b. Free certificate (ACME)">
        <Grid Margin="8">
          <Grid.ColumnDefinitions><ColumnDefinition Width="480"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <DockPanel Grid.Column="0" Margin="0,0,10,0">
          <WrapPanel DockPanel.Dock="Bottom" Margin="0,8,0,0">
            <Button x:Name="LeTestHttpButton" Content="Test HTTP-01 setup" Margin="0,0,8,6"/>
            <Button x:Name="LeRequestButton" Content="Request certificate" FontWeight="Bold" Margin="0,0,8,6"/>
            <Button x:Name="LeCheckDnsButton" Content="Check DNS records" Margin="0,0,8,6"/>
            <Button x:Name="LeContinueButton" Content="Continue (records added)" Margin="0,0,8,6"/>
            <Button x:Name="LeCleanupButton" Content="Clean up challenges" Margin="0,0,8,6"/>
          </WrapPanel>
          <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="0,0,8,0">
              <TextBlock TextWrapping="Wrap" Foreground="DimGray"
                         Text="Gets a free certificate from Let's Encrypt, ZeroSSL, Google, SSL.com or Actalis (via the Posh-ACME module) and hands the PFX to tab 2. Try a Staging provider first: it proves the challenge works without hitting rate limits. Staging certificates are untrusted and cannot be imported."/>
              <DockPanel Margin="0,8,0,0">
                <Button x:Name="LeRecheckModuleButton" DockPanel.Dock="Right" Content="Re-check" Margin="6,0,0,0"/>
                <Button x:Name="LeInstallModuleButton" DockPanel.Dock="Right" Content="Install Posh-ACME" Margin="8,0,0,0"/>
                <TextBlock x:Name="LeModuleText" VerticalAlignment="Center" TextWrapping="Wrap" Text="Posh-ACME: checking..."/>
              </DockPanel>
              <TextBlock Margin="0,10,0,2" Text="Certificate authority:"/>
              <ComboBox x:Name="LeProviderCombo"/>
              <TextBlock x:Name="LeProviderHelpText" Margin="0,4,0,0" TextWrapping="Wrap" Foreground="DimGray"/>
              <TextBlock Margin="0,8,0,2" Text="Contact e-mail for the ACME account (optional; required for ZeroSSL e-mail EAB):"/>
              <TextBox x:Name="LeEmailBox"/>
              <StackPanel x:Name="LeEabPanel" Margin="0,8,0,0" Visibility="Collapsed">
                <DockPanel>
                  <Button x:Name="LeZeroSslEabButton" DockPanel.Dock="Right" Content="Get from e-mail" Margin="8,0,0,0" Visibility="Collapsed"/>
                  <TextBlock VerticalAlignment="Center" Text="EAB key ID (KID):"/>
                </DockPanel>
                <TextBox x:Name="LeEabKidBox" Margin="0,2,0,0" FontFamily="Consolas"/>
                <TextBlock Margin="0,6,0,2" Text="EAB HMAC key (never logged; only needed for the first request):"/>
                <PasswordBox x:Name="LeEabHmacBox"/>
              </StackPanel>
              <CheckBox x:Name="LeTosCheck" Margin="0,6,0,0" Content="I accept the subscriber agreement"/>
              <TextBlock Margin="0,10,0,2" TextWrapping="Wrap"
                         Text="Names (one per line, first = subject). Pre-filled from the certificate currently on IIS:"/>
              <TextBox x:Name="LeNamesBox" Height="90" AcceptsReturn="True" VerticalScrollBarVisibility="Auto" FontFamily="Consolas"/>
              <WrapPanel Margin="0,4,0,0">
                <Button x:Name="LeFillCertButton" Content="Fill from current certificate" Margin="0,0,8,0"/>
                <Button x:Name="LeFillNamesButton" Content="Fill from Exchange URLs"/>
              </WrapPanel>
              <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
                <TextBlock Text="RSA key size:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                <ComboBox x:Name="LeKeyCombo" SelectedIndex="0" Width="90">
                  <ComboBoxItem Content="2048"/><ComboBoxItem Content="3072"/><ComboBoxItem Content="4096"/>
                </ComboBox>
              </StackPanel>
              <TextBlock Margin="0,12,0,4" FontWeight="Bold" Text="Challenge type:"/>
              <RadioButton x:Name="LeHttpRadio" GroupName="LeMode" IsChecked="True" Content="HTTP-01: file in IIS (port 80 from the internet must reach Exchange)"/>
              <TextBlock Margin="20,4,0,2" TextWrapping="Wrap" Text="Webroot of Default Web Site, written on every selected server ({server} and {fqdn} are replaced):"/>
              <TextBox x:Name="LeWebrootBox" Margin="20,0,0,0" FontFamily="Consolas" Text="\\{fqdn}\C$\inetpub\wwwroot"/>
              <RadioButton x:Name="LeDnsManualRadio" GroupName="LeMode" Margin="0,10,0,0" Content="DNS-01 manual: the tool shows TXT records, you create them"/>
              <RadioButton x:Name="LeDnsPluginRadio" GroupName="LeMode" Margin="0,6,0,0" Content="DNS-01 automatic: DNS provider API (Posh-ACME plugin)"/>
              <DockPanel Margin="20,4,0,2">
                <Button x:Name="LePluginParamsButton" DockPanel.Dock="Right" Content="Show parameters" Margin="8,0,0,0"/>
                <ComboBox x:Name="LePluginCombo" IsEditable="True"/>
              </DockPanel>
              <TextBlock Margin="20,2,0,2" TextWrapping="Wrap" Foreground="DimGray"
                         Text="Plugin arguments, one per line as Name=Value. Prefix secrets with secure: (CFToken=secure:abc123). Lists as [a,b]. Values are never logged or saved."/>
              <TextBox x:Name="LePluginArgsBox" Margin="20,0,0,0" Height="70" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
            </StackPanel>
          </ScrollViewer>
          </DockPanel>
          <DockPanel Grid.Column="1">
            <TextBlock x:Name="LeStatusText" DockPanel.Dock="Top" TextWrapping="Wrap" Foreground="DimGray"
                       Text="Challenges, TXT records and test results appear here. The issued PFX is loaded into tab 2 automatically."/>
            <DataGrid x:Name="LeGrid"/>
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

$script:ActionButtons = 'ReloadServersButton', 'RefreshButton', 'BrowseButton', 'ValidateButton', 'ImportButton', 'EnableButton', 'VerifyButton', 'LoadOldButton', 'RemoveButton',
'LeInstallModuleButton', 'LeRecheckModuleButton', 'LeZeroSslEabButton', 'LeFillCertButton', 'LeFillNamesButton', 'LePluginParamsButton', 'LeTestHttpButton', 'LeRequestButton', 'LeCheckDnsButton', 'LeContinueButton', 'LeCleanupButton'

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
    $ui.LeInstallModuleButton.Add_Click({ Invoke-UiAction 'Install Posh-ACME' { Install-PoshAcme } })
    $ui.LeFillNamesButton.Add_Click({ Invoke-UiAction 'Fill names' { Set-LeNamesFromExchange } })
    $ui.LeFillCertButton.Add_Click({ Invoke-UiAction 'Fill from certificate' { [void](Set-LeNamesFromCurrentCert) } })
    foreach ($pr in $script:AcmeProviders) { [void]$ui.LeProviderCombo.Items.Add($pr.Label) }
    $ui.LeProviderCombo.SelectedIndex = 0
    Update-AcmeProviderUi
    $ui.LeProviderCombo.Add_SelectionChanged({ Update-AcmeProviderUi })
    $ui.LeZeroSslEabButton.Add_Click({ Invoke-UiAction 'ZeroSSL EAB' { Get-ZeroSslEab } })
    $ui.LeRecheckModuleButton.Add_Click({ Invoke-UiAction 'Re-check Posh-ACME' { Update-LeModuleStatus } })
    $ui.LePluginParamsButton.Add_Click({ Invoke-UiAction 'Plugin parameters' { Show-LePluginParams } })
    $ui.LeTestHttpButton.Add_Click({ Invoke-UiAction 'HTTP-01 test' { Test-LeHttpSetup } })
    $ui.LeRequestButton.Add_Click({ Invoke-UiAction 'Certificate request' { Start-LeRequest } })
    $ui.LeCheckDnsButton.Add_Click({ Invoke-UiAction 'Check DNS' { [void](Test-LeDnsRecords) } })
    $ui.LeContinueButton.Add_Click({ Invoke-UiAction 'Continue' {
                if (-not @($script:Le.Challenges).Count) { throw 'Nothing to continue - click "Request certificate" first.' }
                Complete-LeRequest } })
    $ui.LeCleanupButton.Add_Click({ Invoke-UiAction 'Clean up' { Clear-LeChallenges } })
    $script:Window.Add_ContentRendered({
            Update-LeModuleStatus
            if (Test-ExchangeAvailable) { Invoke-UiAction 'Load servers' { Update-ServerList; Update-Inventory; Invoke-LeAutoFill } }
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
