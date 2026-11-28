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
                                Step C updates connectors pinned to the old certificate and can pin
                                the new one on 'Default Frontend' (25) / 'Client Frontend' (587).
      4. Verify               - checks Exchange's view and the certificate actually served on
                                HTTPS 443 (and SMTP 25 STARTTLS, informational).
      5. Remove old           - optional; refuses to remove certificates still in use
                                (Auth, internal transport, IIS, pinned by connectors, or unverified server).

    "Dry run" is ON by default: every command is written to the log and nothing is changed.
    Every action is logged to .\logs\CertSwap_<timestamp>.log.

    Also: Auth (OAuth) certificate check/renewal (tab 1), CSR for commercial/internal CAs (tab 2),
    POP/IMAP, rollback snapshots and an Edge Transport package (tab 3), rolling restart (tab 4),
    and unattended ACME renewal for a scheduled task (-Renew).

.PARAMETER LogDirectory
    Folder for log files. Default: <script folder>\logs

.PARAMETER LoadOnly
    Define functions and build the window without connecting to Exchange or showing it.
    For testing:  . .\ExchangeCertTool.ps1 -LoadOnly

.PARAMETER Renew
    Unattended renewal (scheduled task): when the current IIS certificate has fewer than -RenewDays left,
    requests a new ACME certificate with the settings saved by the last successful request in the GUI
    (same Windows user), validates it and runs Step A, B, C and Verify. Dry run unless -Live is given.

.PARAMETER Live
    With -Renew: make the changes (without it, -Renew only logs what it would do).

.PARAMETER RemoveOld
    With -Renew: remove the previous IIS certificate after every server passed verification.

.PARAMETER RenewDays
    With -Renew: renew when the current certificate has fewer days left than this. Default 30.

.PARAMETER ForceRenew
    With -Renew: renew now, regardless of the days left.

.PARAMETER NotifyTo
    With -Renew: e-mail address(es) that receive the run's log when a renewal ran or failed.

.PARAMETER NotifyFrom
    With -Renew: sender address. Default: ExchangeCertTool@<default accepted domain>.

.PARAMETER SmtpServer
    With -Renew: SMTP server for the report. Default: localhost (the Exchange server itself).
#>
[CmdletBinding()]
param(
    [string]$LogDirectory,
    [switch]$LoadOnly,
    [switch]$Renew,
    [switch]$Live,
    [switch]$RemoveOld,
    [int]$RenewDays = 30,
    [switch]$ForceRenew,
    [string[]]$NotifyTo,
    [string]$NotifyFrom,
    [string]$SmtpServer = 'localhost'
)

$ErrorActionPreference = 'Stop'
if (-not $LogDirectory) { $LogDirectory = Join-Path $PSScriptRoot 'logs' }

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'Run this tool in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7 - the Exchange cmdlets and WPF host require it.'
}

# WPF needs an STA thread. powershell.exe 5.1 is STA by default; relaunch if not.
if (-not $LoadOnly -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    if ($Renew) { throw 'Run -Renew in an STA host: powershell.exe -STA -File .\ExchangeCertTool.ps1 -Renew ...' }
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
    AuthConfigRead = $false # Get-AuthConfig answered in the last inventory (Invoke-AuthCertificate needs it)
    AuthNextThumb  = $null  # staged ("next") Auth certificate and the date Exchange makes it current
    AuthNextDate   = $null
    PfxPath      = $null
    PfxPassword  = $null    # SecureString
    NewCert      = $null    # X509Certificate2 (leaf)
    NewThumb     = $null
    NewNames     = @()
    Validated    = $false
    MissingHosts = @()
    Verified     = @{}      # server -> $true when Exchange + HTTPS checks passed
    StagingThumbs = @()     # certificates issued by a staging ACME server in this session
    AuthOtherThumbs = @()   # previous / next Auth certificate (Get-AuthConfig)
    BlockingIssues = @()    # validation findings that would break mail flow (stop -Renew)
}
$script:ui = $null
$script:Window = $null
$script:Unattended = $false   # -Renew: no dialogs, confirmations are automatic
$script:ErrorCount = 0        # ERROR lines written so far (-Renew stops on new errors)

if (-not (Test-Path -LiteralPath $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
$script:LogFile = Join-Path $LogDirectory ('{0}_{1:yyyyMMdd_HHmmss}.log' -f $(if ($Renew) { 'CertRenew' } else { 'CertSwap' }), (Get-Date))

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
    if ($Level -eq 'ERROR') { $script:ErrorCount++ }
    if ($script:ui -and $script:ui.LogBox -and -not $script:Unattended) {
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
    if ($script:Unattended) { Write-Log "$Title - confirmed automatically (unattended run)."; return $true }
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

# One DER element at $Offset: tag, start of its content, end (exclusive).
function Get-DerElement {
    param([byte[]]$Bytes, [int]$Offset)
    $len = [int]$Bytes[$Offset + 1]; $hdr = 2
    if ($len -band 0x80) {
        $n = $len -band 0x7F; $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + $Bytes[$Offset + 2 + $k] }
        $hdr += $n
    }
    [pscustomobject]@{ Tag = [int]$Bytes[$Offset]; Start = $Offset; Content = $Offset + $hdr; End = $Offset + $hdr + $len }
}

# DER SubjectPublicKeyInfo of a certificate (what DANE selector 1 hashes); .NET Framework has no API for it.
function Get-CertSpki {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $b = $Certificate.RawData
    $p = (Get-DerElement $b (Get-DerElement $b 0).Content).Content          # into Certificate, then TBSCertificate
    if ((Get-DerElement $b $p).Tag -eq 0xA0) { $p = (Get-DerElement $b $p).End }   # [0] version
    for ($k = 0; $k -lt 5; $k++) { $p = (Get-DerElement $b $p).End }      # serial, signature, issuer, validity, subject
    $spki = Get-DerElement $b $p
    , [byte[]]$b[$spki.Start..($spki.End - 1)]
}

function ConvertTo-HexString { param([byte[]]$Bytes) [BitConverter]::ToString($Bytes) -replace '-', '' }

# DER SubjectPublicKeyInfo of a PKCS#10 certificate request (base64, PEM text or DER bytes).
function Get-CsrSpki {
    param([Parameter(Mandatory)]$Request)
    [byte[]]$b = if ($Request -is [byte[]]) { $Request } else {
        [Convert]::FromBase64String((("$Request" -replace '-----[^-]+-----', '') -replace '\s', ''))
    }
    $p = (Get-DerElement $b (Get-DerElement $b 0).Content).Content   # into CertificationRequest, then CertificationRequestInfo
    $p = (Get-DerElement $b $p).End                                   # version
    $p = (Get-DerElement $b $p).End                                   # subject
    $spki = Get-DerElement $b $p
    , [byte[]]$b[$spki.Start..($spki.End - 1)]
}

# Public key (hex of the SubjectPublicKeyInfo) of an Exchange pending request, or $null when it cannot be read.
# Windows keeps a placeholder certificate with the request's public key; the request text is the fallback.
function Get-PendingRequestKey {
    param($Pending)
    $x = ConvertTo-X509 $Pending
    if ($x) { try { return (ConvertTo-HexString (Get-CertSpki $x)) } catch { } }
    if ("$($Pending.CertificateRequest)") { try { return (ConvertTo-HexString (Get-CsrSpki "$($Pending.CertificateRequest)")) } catch { } }
    $null
}

# TLSA data as returned by DNS-over-HTTPS: "3 1 1 ab12..." (Google), "3 1 1 ( AB12... )" (Cloudflare), "\# 35 030101ab..." (RFC 3597).
function ConvertFrom-TlsaData {
    param([string]$Data)
    $d = "$Data".Trim()
    if ($d -match '^\\#\s+\d+\s+([0-9A-Fa-f\s]+)$') {
        $hex = $Matches[1] -replace '\s', ''
        if ($hex.Length -lt 8) { return $null }
        return [pscustomobject]@{ Usage = [Convert]::ToInt32($hex.Substring(0, 2), 16); Selector = [Convert]::ToInt32($hex.Substring(2, 2), 16)
            MatchType = [Convert]::ToInt32($hex.Substring(4, 2), 16); Data = $hex.Substring(6).ToUpperInvariant() }
    }
    if ($d -match '^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$') {
        return [pscustomobject]@{ Usage = [int]$Matches[1]; Selector = [int]$Matches[2]; MatchType = [int]$Matches[3]; Data = ($Matches[4] -replace '[\s()]', '').ToUpperInvariant() }
    }
    $null
}

# True when a TLSA record matches: usage 1/3 = the certificate itself, 0/2 = a CA certificate of its chain.
function Test-TlsaMatch {
    param($Record, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf, [object[]]$CaCerts)
    $targets = if ($Record.Usage -in 1, 3) { @($Leaf) } else { @($CaCerts) }
    foreach ($c in $targets) {
        if (-not $c) { continue }
        [byte[]]$data = if ($Record.Selector -eq 1) { Get-CertSpki $c } else { $c.RawData }
        $value = switch ($Record.MatchType) {
            0 { ConvertTo-HexString $data }
            1 { ConvertTo-HexString ([System.Security.Cryptography.SHA256]::Create().ComputeHash($data)) }
            2 { ConvertTo-HexString ([System.Security.Cryptography.SHA512]::Create().ComputeHash($data)) }
            default { $null }
        }
        if ($value -and $value -eq $Record.Data) { return $true }
    }
    $false
}

# Public TLSA records via DNS-over-HTTPS (Resolve-DnsName cannot query TLSA). Empty array = none, $null = lookup failed.
function Get-PublicTlsa {
    param([Parameter(Mandatory)][string]$Name)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $n = [uri]::EscapeDataString($Name)
    foreach ($u in "https://dns.google/resolve?name=$n&type=TLSA", "https://cloudflare-dns.com/dns-query?name=$n&type=TLSA") {
        try {
            $r = Invoke-RestMethod -Uri $u -Headers @{ Accept = 'application/dns-json' } -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
            return , @(@($r.Answer) | Where-Object { $_ -and [int]$_.type -eq 52 } | ForEach-Object { ConvertFrom-TlsaData "$($_.data)" } | Where-Object { $_ })
        }
        catch { }
    }
    $null
}

# X509Certificate2 (public part only) of an Exchange certificate object - live, or deserialized with RawData.
function ConvertTo-X509 {
    param($ExCert)
    if (-not $ExCert) { return $null }
    if ($ExCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { return $ExCert }
    try { if ($ExCert.RawData) { return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$ExCert.RawData)) } } catch { }
    $null
}

# EKU OIDs of a certificate; 'any' when it has no EKU extension (valid for every purpose).
function Get-CertEkus {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $e = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (-not $e) { return , @('any') }
    , @($e.EnhancedKeyUsages | ForEach-Object { $_.Value })
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
                Certificate  = $remote
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

function Get-ServerFqdn {
    param([string]$Server)
    if ($script:State.Servers.ContainsKey($Server) -and $script:State.Servers[$Server].Fqdn) { return $script:State.Servers[$Server].Fqdn }
    $Server
}

# The hybrid configuration object, or $null when the organization is not hybrid.
function Get-HybridConfigSafe {
    if (-not (Get-Command Get-HybridConfiguration -ErrorAction SilentlyContinue)) { return $null }
    try { Get-HybridConfiguration -ErrorAction Stop } catch { $null }
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
    $authConfig = $null
    $script:State.AuthConfigRead = $false
    try {
        $authConfig = Get-AuthConfig -ErrorAction Stop
        $script:State.AuthConfigRead = $true
        $script:State.AuthThumb = "$($authConfig.CurrentCertificateThumbprint)"
        $script:State.AuthOtherThumbs = @("$($authConfig.PreviousCertificateThumbprint)", "$($authConfig.NextCertificateThumbprint)" | Where-Object { $_ })
        $script:State.AuthNextThumb = "$($authConfig.NextCertificateThumbprint)"
        $script:State.AuthNextDate = $null
        if ($script:State.AuthNextThumb -and $authConfig.NextCertificateEffectiveDate) { try { $script:State.AuthNextDate = [datetime]$authConfig.NextCertificateEffectiveDate } catch { } }
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
    if ($authConfig) { Test-AuthCertificate -Rows $rows.ToArray() -Servers $servers -AuthConfig $authConfig }
}

# Logs the Auth (OAuth) certificate's expiry and the servers that miss it.
function Test-AuthCertificate {
    param([object[]]$Rows, [string[]]$Servers, $AuthConfig)
    $thumb = $script:State.AuthThumb
    $fix = 'Use "Renew / copy Auth certificate" on tab 1.'
    if (-not $thumb) { Write-Log "No Auth (OAuth) certificate is configured (Get-AuthConfig). OAuth (hybrid free/busy, OWA/ECP sign-in) needs one. $fix" WARN; return }
    $have = @($Rows | Where-Object { $_.Thumbprint -eq $thumb })
    $missing = @($Servers | Where-Object { $_ -notin @($have | ForEach-Object { $_.Server }) })
    if ($have) {
        $days = ($have | Measure-Object DaysLeft -Minimum).Minimum
        $msg = 'Auth (OAuth) certificate expires {0:yyyy-MM-dd} ({1} days left).' -f $have[0].NotAfter, $days
        if ($days -lt 0) { Write-Log "$msg EXPIRED: OAuth fails (hybrid free/busy, OWA/ECP sign-in). $fix" ERROR }
        elseif ($days -lt 60) { Write-Log "$msg Renew it soon. $fix" WARN }
        else { Write-Log $msg }
    }
    if ($missing) { Write-Log "The Auth (OAuth) certificate $thumb is missing on $($missing -join ', '): OAuth fails on those servers. $fix" WARN }
    $next = "$($script:State.AuthNextThumb)"; $nextDate = $script:State.AuthNextDate
    if ($next -and $next -ne $thumb) {
        $nextHave = @($Rows | Where-Object { $_.Thumbprint -eq $next } | ForEach-Object { $_.Server })
        $nextMissing = @($Servers | Where-Object { $_ -notin $nextHave })
        if ($nextDate -and $nextDate -lt (Get-Date).AddHours(-13)) {
            Write-Log ('The next Auth certificate {0} was due on {1:yyyy-MM-dd HH:mm}, but Exchange has not made it current yet. The AuthAdmin servicelet may not run: restart MSExchangeServiceHost on one server, then look for event 2014 (MSExchange AuthAdmin) and in <ExchangeInstallPath>\Logging\AuthAdminLogs.' -f $next, $nextDate) WARN
        }
        else { Write-Log ('Next Auth certificate {0} is scheduled: Exchange makes it current by itself on {1}.' -f $next, $(if ($nextDate) { $nextDate.ToString('yyyy-MM-dd HH:mm') } else { '(no date)' })) }
        if ($nextMissing) { Write-Log "The next Auth certificate $next is missing on $($nextMissing -join ', '): copy it before the switch. $fix" WARN }
    }
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
    $hc = Get-HybridConfigSafe
    if ($hc -and "$($hc.TlsCertificateName)") { $items.Add([pscustomobject]@{ Type = 'Hybrid'; Identity = 'HybridConfiguration'; Tls = "$($hc.TlsCertificateName)" }) }
    foreach ($i in $items) {
        $issuer = ''; $subject = ''
        if ($i.Tls -match '^<I>(.*?)<S>(.*)$') { $issuer = $Matches[1]; $subject = $Matches[2] }
        $key = (ConvertTo-NormalizedDn $issuer) + '|' + (ConvertTo-NormalizedDn $subject)
        $matchNew = ($key -eq $newKey)
        $oldThumbs = @($OldCerts | Where-Object { ((ConvertTo-NormalizedDn $_.Issuer) + '|' + (ConvertTo-NormalizedDn $_.Subject)) -eq $key } |
                Select-Object -ExpandProperty Thumbprint -Unique)
        $tlsNew = ("<I>{0}<S>{1}" -f $NewIssuer, $NewSubject) -replace "'", "''"
        if ($matchNew) { $status = 'OK - new certificate has the same issuer/subject, Exchange will pick it up' }
        elseif ($oldThumbs) { $status = 'ACTION - pinned to the OLD certificate; update before removing the old one' }
        else { $status = 'INFO - references a different certificate (not old, not new)' }
        $fix = switch ($i.Type) {
            'Send' { "Set-SendConnector -Identity '{0}' -TlsCertificateName '{1}'" -f ($i.Identity -replace "'", "''"), $tlsNew }
            'Hybrid' { "Set-HybridConfiguration -TlsCertificateName '{0}'" -f $tlsNew }
            default { "Set-ReceiveConnector -Identity '{0}' -TlsCertificateName '{1}'" -f ($i.Identity -replace "'", "''"), $tlsNew }
        }
        $i | Add-Member -NotePropertyName MatchesNew -NotePropertyValue $matchNew
        $i | Add-Member -NotePropertyName OldThumbprints -NotePropertyValue ($oldThumbs -join ',')
        $i | Add-Member -NotePropertyName Status -NotePropertyValue $status
        $i | Add-Member -NotePropertyName FixCommand -NotePropertyValue $fix
    }
    $items.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Step 3C: SMTP connectors (TlsCertificateName)
# ---------------------------------------------------------------------------------------------
function Test-TlsNameMatches {
    param([string]$Tls, [string]$Issuer, [string]$Subject)
    if ($Tls -notmatch '^<I>(.*?)<S>(.*)$') { return $false }
    $ti = $Matches[1]; $ts = $Matches[2]
    ((ConvertTo-NormalizedDn $ti) -eq (ConvertTo-NormalizedDn $Issuer)) -and ((ConvertTo-NormalizedDn $ts) -eq (ConvertTo-NormalizedDn $Subject))
}

function Get-ConnectorPorts { param($Connector) @(@($Connector.Bindings) | ForEach-Object { ("$_" -split ':')[-1] } | Where-Object { $_ } | Select-Object -Unique) }

function Test-FrontendConnector {
    param($Connector, [string]$Port)
    ("$($Connector.TransportRole)" -match 'Frontend') -and ((Get-ConnectorPorts $Connector) -contains $Port)
}

# Builds the list of connector changes for the validated certificate.
# Action: 'update' = pinned to the old certificate, 'pin' = frontend connector without a pinned certificate, 'none' = no change.
function Get-ConnectorPlan {
    Assert-Exchange; Assert-Validated
    $servers = Get-SelectedServers
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    $new = $script:State.NewCert
    if (-not $script:State.Inventory) { Update-Inventory }
    $oldCerts = @($script:State.Inventory | Where-Object { $_.SelfSigned -ne 'True' -and $_.Thumbprint -ne $script:State.NewThumb })
    $pinFrontend = [bool]$script:ui.PinFrontendCheck.IsChecked
    $pinClient = [bool]$script:ui.PinClientCheck.IsChecked
    $rows = New-Object System.Collections.Generic.List[object]

    $classify = {
        param([string]$Tls)
        if (Test-TlsNameMatches $Tls $new.Issuer $new.Subject) { return @('none', 'OK - already pinned to the new certificate (same issuer and subject)') }
        if ($oldCerts | Where-Object { Test-TlsNameMatches $Tls $_.Issuer $_.Subject }) { return @('update', 'Pinned to the OLD certificate - will be switched to the new one') }
        return @('none', 'Pinned to another certificate (not old, not new) - left alone')
    }

    try {
        foreach ($c in @(Get-SendConnector)) {
            $tls = "$($c.TlsCertificateName)"
            if (-not $tls) { continue }
            $a = & $classify $tls
            $rows.Add([pscustomobject]@{ Action = $a[0]; Type = 'Send'; Server = (@($c.SourceTransportServers | ForEach-Object { "$_" }) -join ','); Connector = "$($c.Identity)"
                    Ports = ''; Fqdn = "$($c.Fqdn)"; Current = $tls; Note = $a[1] })
        }
    }
    catch { Write-Log "Get-SendConnector failed: $($_.Exception.Message)" WARN }

    # The HCW reads TlsCertificateName from the hybrid configuration when it (re)configures the connectors.
    $hc = Get-HybridConfigSafe
    if ($hc -and "$($hc.TlsCertificateName)") {
        $tls = "$($hc.TlsCertificateName)"
        $a = & $classify $tls
        $rows.Add([pscustomobject]@{ Action = $a[0]; Type = 'Hybrid'; Server = ''; Connector = 'HybridConfiguration'; Ports = ''; Fqdn = ''; Current = $tls
                Note = "$($a[1]) (Hybrid Configuration Wizard setting)" })
    }

    foreach ($s in $servers) {
        try { $conns = @(Get-ReceiveConnector -Server $s) }
        catch { Write-Log "${s}: Get-ReceiveConnector failed: $($_.Exception.Message)" WARN; continue }
        foreach ($c in $conns) {
            $tls = "$($c.TlsCertificateName)"
            $ports = Get-ConnectorPorts $c
            $is25 = Test-FrontendConnector $c '25'
            $is587 = Test-FrontendConnector $c '587'
            if ($tls) { $a = & $classify $tls }
            elseif ($is25 -or $is587) {
                $fqdn = "$($c.Fqdn)"
                if ($fqdn -and (Test-HostCovered -HostName $fqdn -CertNames $script:State.NewNames)) {
                    $a = @('none', "OK - FQDN $fqdn is on the new certificate, so Exchange selects it automatically")
                }
                elseif (($is25 -and $pinFrontend) -or ($is587 -and $pinClient)) {
                    $a = @('pin', "Not pinned; FQDN $fqdn is not on the new certificate, so STARTTLS currently offers the server's own (usually self-signed) certificate - will pin the new one")
                }
                else { $a = @('none', "Not pinned; STARTTLS offers the certificate matching FQDN $fqdn (usually self-signed). Tick the option above to pin the new certificate.") }
            }
            else { continue }
            $rows.Add([pscustomobject]@{ Action = $a[0]; Type = 'Receive'; Server = $s; Connector = "$($c.Identity)"; Ports = ($ports -join ',')
                    Fqdn = "$($c.Fqdn)"; Current = $(if ($tls) { $tls } else { '(none)' }); Note = $a[1] })
        }
    }
    $rows.ToArray()
}

function Show-ConnectorPlan {
    param([object[]]$Plan)
    $script:ui.ConnectorGrid.ItemsSource = (ConvertTo-DataTable $Plan @('Action', 'Type', 'Server', 'Connector', 'Ports', 'Fqdn', 'Current', 'Note')).DefaultView
    $n = @($Plan | Where-Object { $_.Action -ne 'none' }).Count
    Write-Log ("Connector plan: {0} connector(s) listed, {1} to change." -f @($Plan).Count, $n)
}

function Update-ConnectorPreview { Show-ConnectorPlan -Plan @(Get-ConnectorPlan) }

function Invoke-UpdateConnectors {
    $plan = @(Get-ConnectorPlan)
    Show-ConnectorPlan -Plan $plan
    $todo = @($plan | Where-Object { $_.Action -ne 'none' })
    if (-not $todo) { Write-Log 'No connector needs a change.' OK; return }
    $new = $script:State.NewCert
    $thumb = $script:State.NewThumb
    $tlsNew = "<I>$($new.Issuer)<S>$($new.Subject)"

    # The certificate must be on the server and enabled for SMTP, or STARTTLS breaks (event 12014).
    $readyCache = @{}
    $isReady = {
        param([string]$Server)
        if (-not $readyCache.ContainsKey($Server)) {
            $c = Get-ExchangeCertSafe -Server $Server -Thumbprint $thumb
            $readyCache[$Server] = [bool]($c -and ((Get-ServiceList $c) -contains 'SMTP'))
        }
        $readyCache[$Server]
    }
    $blocked = New-Object System.Collections.Generic.List[object]
    foreach ($r in $todo) {
        $srvs = @($r.Server -split ',' | Where-Object { $_ })
        $notReady = @($srvs | Where-Object { -not (& $isReady $_) })
        if ($notReady) { $blocked.Add([pscustomobject]@{ Row = $r; Servers = $notReady }) }
    }
    if ($blocked.Count) {
        foreach ($b in $blocked) {
            Write-Log "$($b.Row.Connector): the new certificate is not enabled for SMTP on $($b.Servers -join ', ') yet - run Step A and Step B first$(if (Test-DryRun) { ' (dry run continues)' })." $(if (Test-DryRun) { 'WARN' } else { 'ERROR' })
        }
        if (-not (Test-DryRun)) { $todo = @($todo | Where-Object { $_ -notin @($blocked | ForEach-Object { $_.Row }) }) }
        if (-not $todo) { throw 'No connector can be changed until the new certificate is enabled for SMTP on the servers (tab 3, Step B).' }
    }

    $list = ($todo | ForEach-Object { "  [$($_.Action)] $($_.Type) $($_.Connector)" }) -join "`n"
    $msg = "Set TlsCertificateName on these connectors to:`n  $tlsNew`n`n$list`n`nThe previous values are written to the log as rollback commands."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Update SMTP connectors')) { Write-Log 'Connector update cancelled.' WARN; return }
    try { Save-ChangeSnapshot -Before 'StepC' } catch { Write-Log "Could not save the rollback snapshot: $($_.Exception.Message)" WARN }

    $q = { param([string]$s) "'" + ($s -replace "'", "''") + "'" }
    foreach ($r in $todo) {
        $cmd = switch ($r.Type) { 'Send' { 'Set-SendConnector' } 'Hybrid' { 'Set-HybridConfiguration' } default { 'Set-ReceiveConnector' } }
        $idArg = if ($r.Type -eq 'Hybrid') { '' } else { " -Identity $(& $q $r.Connector)" }
        $prev = if ($r.Current -and $r.Current -ne '(none)') { & $q $r.Current } else { '$null' }
        Write-Log "Rollback for $($r.Connector): $cmd$idArg -TlsCertificateName $prev"
        try {
            Invoke-Step "$cmd$idArg -TlsCertificateName $(& $q $tlsNew)" {
                if ($r.Type -eq 'Send') {
                    Set-SendConnector -Identity $r.Connector -TlsCertificateName $tlsNew -ErrorAction Stop
                    $now = "$((Get-SendConnector -Identity $r.Connector).TlsCertificateName)"
                }
                elseif ($r.Type -eq 'Hybrid') {
                    Set-HybridConfiguration -TlsCertificateName $tlsNew -ErrorAction Stop
                    $now = "$((Get-HybridConfiguration).TlsCertificateName)"
                }
                else {
                    Set-ReceiveConnector -Identity $r.Connector -TlsCertificateName $tlsNew -ErrorAction Stop
                    $now = "$((Get-ReceiveConnector -Identity $r.Connector).TlsCertificateName)"
                }
                if (Test-TlsNameMatches $now $new.Issuer $new.Subject) { Write-Log "$($r.Connector): now uses the new certificate." OK }
                else { Write-Log "$($r.Connector): TlsCertificateName is '$now' after the change - check it manually." ERROR }
            }
        }
        catch { Write-Log "$($r.Connector): update FAILED: $($_.Exception.Message)" ERROR }
    }
    if (-not (Test-DryRun)) {
        Show-ConnectorPlan -Plan @(Get-ConnectorPlan)
        Write-Log 'Transport picks up connector changes automatically within a few minutes. Then run tab 4 (Verify) - SMTP port 25 should serve the new certificate.' INFO
    }
}

# Read-only checks that protect mail flow when the certificate changes: Client Authentication EKU, the name
# Exchange Online checks on hybrid mail, MX names that would drop off the certificate, and DANE TLSA records.
# Findings that would break mail flow also go to $script:State.BlockingIssues (they stop -Renew).
function Add-MailFlowChecks {
    param([System.Text.StringBuilder]$Report, $Warnings, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf, [object[]]$ExtraCerts, [string[]]$Names)
    $out = { param([string]$t = '') [void]$Report.AppendLine($t) }
    $block = { param([string]$m) $Warnings.Add($m); $script:State.BlockingIssues += $m }
    & $out '=== MAIL FLOW (EKU, hybrid, MX, DANE) ==='
    $old = @()
    try { $old = @(Get-CurrentIisCertificates | Where-Object { -not $Leaf -or $_.Thumbprint -ne $Leaf.Thumbprint }) } catch { }
    $oldNames = @($old | ForEach-Object { $_.Domains; if ("$($_.Subject)" -match '(?:^|,\s*)CN=([^,]+)') { $Matches[1].Trim() } } |
        Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() } | Select-Object -Unique)

    if ($Leaf) {
        $ekus = Get-CertEkus $Leaf
        $ekuText = if ($ekus -contains 'any') { '(no EKU extension = any purpose)' } else { (@($ekus | ForEach-Object { $f = (New-Object System.Security.Cryptography.Oid $_).FriendlyName; if ($f) { $f } else { $_ } }) -join ', ') }
        & $out "  EKU: $ekuText"
        if (-not (($ekus -contains '1.3.6.1.5.5.7.3.2') -or ($ekus -contains 'any'))) {
            $oldHad = $false
            foreach ($o in $old) {
                $x = ConvertTo-X509 (Get-ExchangeCertSafe -Server @($o.Servers)[0] -Thumbprint $o.Thumbprint)
                if ($x) { $e = Get-CertEkus $x; if (($e -contains '1.3.6.1.5.5.7.3.2') -or ($e -contains 'any')) { $oldHad = $true } }
            }
            if ($oldHad) { $Warnings.Add('The new certificate has no Client Authentication EKU, but the current one has. Exchange also presents this certificate as a client on outgoing SMTP, so partners that require mutual TLS (domain security) may reject it. Public CAs are phasing this EKU out.') }
            else { & $out '  [INFO] No Client Authentication EKU (normal for current public certificates).' }
        }
    }

    $hc = Get-HybridConfigSafe
    if ($hc -and "$($hc.TlsCertificateName)" -match '<S>(.*)$') {
        $subj = $Matches[1]
        $cn = if ($subj -match '(?:^|,\s*)CN=([^,]+)') { $Matches[1].Trim().ToLowerInvariant() } else { $null }
        $ok = if (-not $cn) { $true } elseif ($cn.StartsWith('*.')) { $Names -contains $cn } else { Test-HostCovered -HostName $cn -CertNames $Names }
        if (-not $cn) { & $out '  [INFO] Hybrid configuration found, but its certificate subject has no CN.' }
        elseif ($ok) { & $out "  [ OK ] Hybrid: $cn is on the new certificate (Exchange Online checks this name on mail from on-premises)." }
        else {
            $m = "Hybrid: the new certificate does not contain $cn. Exchange Online checks the on-premises certificate by name (inbound connector TlsSenderCertificateName, outbound connector TlsDomain), so hybrid mail flow fails until those names are changed. Run tab 3, Step D (Exchange Online connectors) right after Step C, or rerun the Hybrid Configuration Wizard with 'Update Secure Mail Certificate for connectors'."
            if ($script:Unattended) { & $block "$m Unattended renewals never change names." } else { $Warnings.Add($m) }
        }
    }

    $ca = @()
    if ($Leaf) {
        $ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $ch.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        foreach ($e in @($ExtraCerts)) { if ($e) { [void]$ch.ChainPolicy.ExtraStore.Add($e) } }
        try { [void]$ch.Build($Leaf); $ca = @($ch.ChainElements | Select-Object -Skip 1 | ForEach-Object { $_.Certificate }) } catch { }
        $ca += @($ExtraCerts | Where-Object { $_ -and $_.Thumbprint -ne $Leaf.Thumbprint })
    }
    $domains = @()
    try {
        $domains = @(Get-AcceptedDomain | Where-Object { "$($_.DomainType)" -eq 'Authoritative' -and "$($_.DomainName)" -notmatch '\*' } |
            ForEach-Object { "$($_.DomainName)".ToLowerInvariant() } | Where-Object { $_ -notmatch $script:LeInternalNamePattern } | Select-Object -First 20)
    }
    catch { Write-Log "Get-AcceptedDomain failed: $($_.Exception.Message)" WARN }
    $doh = $true
    foreach ($d in $domains) {
        $mx = @(Resolve-PublicName -Name $d -Type MX | Where-Object { $_.Type -eq 'MX' } | ForEach-Object { "$($_.NameExchange)".TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
        foreach ($m in $mx) {
            $onNew = Test-HostCovered -HostName $m -CertNames $Names
            $onOld = $oldNames.Count -and (Test-HostCovered -HostName $m -CertNames $oldNames)
            if ($onOld -and -not $onNew) { & $block "MX $m ($d) is on the current certificate but not on the new one. Senders that enforce TLS (MTA-STS, DANE, partner TLS) would fail once port 25 serves the new certificate."; continue }
            if (-not $onNew) { continue }   # this MX is not these servers (e.g. Exchange Online Protection or a mail gateway)
            if (-not $Leaf -or -not $doh) { continue }
            $recs = Get-PublicTlsa "_25._tcp.$m"
            if ($null -eq $recs) { $doh = $false; & $out '  [INFO] DANE check skipped: no HTTPS access to dns.google or cloudflare-dns.com.'; continue }
            if (-not $recs.Count) { & $out "  [ OK ] MX $m ($d) is on the new certificate; no DANE TLSA records."; continue }
            if (@($recs | Where-Object { Test-TlsaMatch -Record $_ -Leaf $Leaf -CaCerts $ca }).Count) { & $out "  [ OK ] DANE: a TLSA record of _25._tcp.$m matches the new certificate." }
            else {
                $hash = ConvertTo-HexString ([System.Security.Cryptography.SHA256]::Create().ComputeHash((Get-CertSpki $Leaf)))
                & $block "DANE: no TLSA record of _25._tcp.$m matches the new certificate. Publish '_25._tcp.$m TLSA 3 1 1 $hash' next to the existing record and wait for its TTL before Step B/C, or senders that validate DANE (including Exchange Online) stop delivering mail for $d."
            }
        }
    }
    if (-not $domains) { & $out '  [INFO] No accepted domains to check MX/DANE for.' }
    & $out ''
}

# ---------------------------------------------------------------------------------------------
# Step 2 alternatives: a certificate that is already installed, or one Posh-ACME saved earlier
# ---------------------------------------------------------------------------------------------
# One entry per CA-issued certificate found on the selected servers (from the inventory).
function Get-InstalledCertChoices {
    if (-not $script:State.Inventory) { Update-Inventory }
    $rows = @($script:State.Inventory | Where-Object { $_.SelfSigned -ne 'True' })
    foreach ($g in $rows | Group-Object Thumbprint) {
        $r = $g.Group[0]
        $onIis = @($g.Group | Where-Object { ($_.Services -split ',') -contains 'IIS' } | ForEach-Object { $_.Server })
        [pscustomobject]@{
            Thumbprint = $r.Thumbprint; Subject = $r.Subject; Issuer = $r.Issuer; NotAfter = $r.NotAfter
            Domains    = @("$($r.Domains)" -split '\s*,\s*' | Where-Object { $_ })
            Servers    = @($g.Group | ForEach-Object { $_.Server }); IisServers = $onIis
            Label      = ('{0}  exp {1:yyyy-MM-dd}  {2}  on {3}{4}' -f $r.Subject, $r.NotAfter, $r.Thumbprint.Substring(0, [Math]::Min(8, $r.Thumbprint.Length)),
                ((@($g.Group | ForEach-Object { $_.Server })) -join ', '), $(if ($onIis) { "  [IIS: $($onIis -join ', ')]" } else { '' }))
        }
    }
}

function Update-InventoryAndInstalled { Update-Inventory; Update-InstalledCertList }

function Update-InstalledCertList {
    Assert-Exchange
    $choices = @(Get-InstalledCertChoices | Sort-Object @{ e = { [bool]$_.IisServers.Count }; Descending = $true }, @{ e = { $_.NotAfter }; Descending = $true })
    $script:InstalledChoices = $choices
    $script:ui.InstalledCertCombo.Items.Clear()
    foreach ($c in $choices) { [void]$script:ui.InstalledCertCombo.Items.Add($c.Label) }
    if ($choices) { $script:ui.InstalledCertCombo.SelectedIndex = 0 }
    Write-Log "Found $($choices.Count) CA-issued certificate(s) installed on the selected servers."
}

# Uses a certificate that is already in Exchange (e.g. issued earlier and already bound to IIS)
# as the "new" certificate - no PFX needed for Step B/C, Verify and Remove old.
function Invoke-UseInstalledCertificate {
    Assert-Exchange
    if (-not $script:InstalledChoices) { Update-InstalledCertList }
    $i = $script:ui.InstalledCertCombo.SelectedIndex
    if ($i -lt 0 -or $i -ge @($script:InstalledChoices).Count) { throw 'No installed CA-issued certificate found on the selected servers.' }
    $c = $script:InstalledChoices[$i]
    $servers = @(Get-SelectedServers)

    $script:ui.PfxPathBox.Text = ''
    $script:ui.PfxPasswordBox.Password = ''
    Reset-Validation

    $sb = New-Object System.Text.StringBuilder
    $out = { param([string]$t = '') [void]$sb.AppendLine($t) }
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $days = [int][math]::Floor(([datetime]$c.NotAfter - (Get-Date)).TotalDays)
    $cn = if ("$($c.Subject)" -match '(?:^|,\s*)CN=([^,]+)') { $Matches[1].Trim().ToLowerInvariant() } else { $null }
    $names = @(@($c.Domains | ForEach-Object { "$_".ToLowerInvariant() }) + @($cn) | Where-Object { $_ } | Select-Object -Unique)

    & $out '=== INSTALLED CERTIFICATE (no PFX) ==='
    & $out "Subject     : $($c.Subject)"
    & $out "Issuer      : $($c.Issuer)"
    & $out "Thumbprint  : $($c.Thumbprint)"
    & $out ("Expires     : {0:yyyy-MM-dd}  ({1} days left)" -f $c.NotAfter, $days)
    & $out "Names       : $($names -join ', ')"
    & $out ''
    & $out '=== WHERE IT IS ==='
    foreach ($s in $servers) {
        $row = $script:State.Inventory | Where-Object { $_.Server -eq $s -and $_.Thumbprint -eq $c.Thumbprint } | Select-Object -First 1
        if ($row) { & $out ("  {0,-12} present, services: {1}" -f $s, $(if ($row.Services) { $row.Services } else { 'None' })) }
        else { & $out ("  {0,-12} NOT present - Step A copies it from {1} (needs an exportable private key)" -f $s, ($c.Servers -join ', ')) }
    }
    & $out ''

    if ([datetime]$c.NotAfter -lt (Get-Date)) { $errors.Add('Certificate is EXPIRED.') }
    elseif ($days -lt 30) { $warnings.Add("Certificate expires in $days days.") }
    if ("$($c.Issuer)" -match '\(STAGING\)|Fake LE|Pebble|\bTest\b|Staging') { $errors.Add('This is a STAGING/test certificate - clients do not trust it.') }

    $missing = @()
    if ($servers) {
        & $out '=== HOST NAMES USED BY EXCHANGE ==='
        foreach ($g in (@(Get-ExchangeHostNames -Servers $servers) | Group-Object Host | Sort-Object Name)) {
            $ok = Test-HostCovered -HostName $g.Name -CertNames $names
            & $out ("  [{0}] {1}" -f $(if ($ok) { ' OK ' } else { 'MISS' }), $g.Name)
            if (-not $ok) { $missing += $g.Name }
        }
        if ($missing) { $warnings.Add("Not covered by the certificate: $($missing -join ', ')") }
        & $out ''
        $x509 = ConvertTo-X509 (Get-ExchangeCertSafe -Server @($c.Servers)[0] -Thumbprint $c.Thumbprint)
        if (-not $x509) { & $out '(EKU and DANE checks skipped: the certificate data is not available from Exchange.)' }
        try { Add-MailFlowChecks -Report $sb -Warnings $warnings -Leaf $x509 -Names $names }
        catch { Write-Log "Mail flow checks failed: $($_.Exception.Message)" WARN }
    }

    & $out '=== RESULT ==='
    foreach ($e in $errors) { & $out "  ERROR: $e" }
    foreach ($w in $warnings) { & $out "  WARN : $w" }
    if (-not $errors.Count) {
        & $out '  Using this certificate. Next: tab 3 (Step B/C as needed), tab 4 Verify, tab 5 Remove old.'
        $script:State.Validated = $true
        $script:State.NewCert = [pscustomobject]@{ Subject = "$($c.Subject)"; Issuer = "$($c.Issuer)"; Thumbprint = "$($c.Thumbprint)"; NotAfter = $c.NotAfter }
        $script:State.NewThumb = "$($c.Thumbprint)"
        $script:State.NewNames = $names
        $script:State.PfxPath = $null
        $script:State.PfxPassword = $null
        $script:State.MissingHosts = $missing
        $script:State.Verified = @{}
    }
    $script:ui.ValidationBox.Text = $sb.ToString()
    if ($errors.Count) { Write-Log "Installed certificate $($c.Thumbprint) cannot be used: $($errors -join ' ')" ERROR; return }
    Write-Log "Using installed certificate $($c.Thumbprint) ($($c.Subject)) as the new certificate - no PFX needed." OK
    try { Update-ConnectorPreview } catch { Write-Log "Connector preview failed: $($_.Exception.Message)" WARN }
}

function Get-PoshAcmeHome {
    if ($env:POSHACME_HOME) {
        $h = [Environment]::ExpandEnvironmentVariables($env:POSHACME_HOME)
        if (Test-Path -LiteralPath $h) { return $h }
    }
    Join-Path $env:LOCALAPPDATA 'Posh-ACME'
}

# Finds certificates Posh-ACME saved earlier (fullchain.pfx next to order.json), newest first.
function Find-AcmeSavedCertificates {
    $root = Get-PoshAcmeHome
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    foreach ($pfx in @(Get-ChildItem -LiteralPath $root -Filter 'fullchain.pfx' -Recurse -File -ErrorAction SilentlyContinue)) {
        $orderFile = Join-Path $pfx.DirectoryName 'order.json'
        $pw = ''; $main = $pfx.Directory.Name; $expires = $null
        if (Test-Path -LiteralPath $orderFile) {
            try {
                $o = Get-Content -LiteralPath $orderFile -Raw | ConvertFrom-Json
                if ($o.PfxPassB64U) {
                    $b = "$($o.PfxPassB64U)".Replace('-', '+').Replace('_', '/')
                    switch ($b.Length % 4) { 2 { $b += '==' } 3 { $b += '=' } }
                    $pw = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b))
                }
                elseif ($o.PfxPass) { $pw = "$($o.PfxPass)" }
                if ($o.MainDomain) { $main = "$($o.MainDomain)" }
                if ($o.CertExpires) { $expires = [datetime]::Parse("$($o.CertExpires)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) }
            }
            catch { }
        }
        # Thumbprint from cert.cer (public certificate only - no private key is read or stored).
        $thumb = $null
        $cer = Join-Path $pfx.DirectoryName 'cert.cer'
        if (Test-Path -LiteralPath $cer) {
            try { $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [IO.File]::ReadAllBytes($cer))).Thumbprint } catch { }
        }
        [pscustomobject]@{ Path = $pfx.FullName; Password = $pw; MainDomain = $main; Expires = $expires; Written = $pfx.LastWriteTime; Thumbprint = $thumb
            Server = (Split-Path (Split-Path (Split-Path $pfx.DirectoryName -Parent) -Parent) -Leaf) }
    }
}

function Invoke-LoadAcmeSaved {
    $found = @(Find-AcmeSavedCertificates | Sort-Object Written -Descending)
    if (-not $found) { throw "No certificate saved by Posh-ACME was found under $(Get-PoshAcmeHome) for $env:USERNAME. If it was issued under another Windows account, run the tool as that user, or use the installed certificate instead." }
    foreach ($f in $found) { Write-Log ("Posh-ACME certificate: {0}  ({1}, saved {2:yyyy-MM-dd HH:mm}{3})  {4}" -f $f.MainDomain, $f.Server, $f.Written, $(if ($f.Expires) { ", expires {0:yyyy-MM-dd}" -f $f.Expires } else { '' }), $f.Path) }
    $pick = $found[0]
    $script:ui.PfxPathBox.Text = $pick.Path
    $script:ui.PfxPasswordBox.Password = $pick.Password
    Write-Log "Loaded the newest Posh-ACME certificate ($($pick.MainDomain), $($pick.Server)). Validating..." OK
    Invoke-ValidatePfx
}

# ---------------------------------------------------------------------------------------------
# Step 2: validate PFX
# ---------------------------------------------------------------------------------------------
function Reset-Validation {
    if ($script:State.Validated) { Write-Log 'PFX path or password changed - validation reset, please validate again.' WARN }
    $script:State.Validated = $false
    $script:State.NewCert = $null
    $script:State.NewThumb = $null
    $script:State.BlockingIssues = @()
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
            if (-not $c.MatchesNew) { & $out ("      Fix (tab 3, Step C does this for you): {0}" -f $c.FixCommand) }
        }
        if ($conns | Where-Object { $_.Status -like 'ACTION*' }) { $warnings.Add('One or more connectors pin the OLD certificate - see the connector section.') }
        & $out ''
        try { Add-MailFlowChecks -Report $sb -Warnings $warnings -Leaf $leaf -ExtraCerts $others -Names $allNames }
        catch { Write-Log "Mail flow checks failed: $($_.Exception.Message)" WARN }
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
    else {
        Write-Log ("Validation passed for {0} ({1} warning(s))." -f $leaf.Thumbprint, $warnings.Count) OK
        if ((Test-ExchangeAvailable) -and (Get-SelectedServers)) {
            try { Update-ConnectorPreview } catch { Write-Log "Connector preview failed: $($_.Exception.Message)" WARN }
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Step 3: import + enable
# ---------------------------------------------------------------------------------------------
# Step A when the certificate came from Exchange instead of a PFX: export it from a server that has it
# (needs an exportable private key) and import it on the selected servers that do not.
function Copy-InstalledCertificate {
    param([string[]]$Servers, [bool]$Exportable, [string]$Thumbprint)
    $thumb = if ($Thumbprint) { $Thumbprint } else { $script:State.NewThumb }
    $have = @(); $need = @()
    foreach ($s in $Servers) { if (Get-ExchangeCertSafe -Server $s -Thumbprint $thumb) { $have += $s } else { $need += $s } }
    if (-not $need) { Write-Log "Certificate $thumb is already on all selected servers - nothing to import. Continue with Step B / Step C." OK; return }
    if (-not $have) {
        $others = @($script:State.Servers.Keys | Where-Object { $_ -notin $Servers -and (Get-ExchangeCertSafe -Server $_ -Thumbprint $thumb) })
        $have = $others
    }
    $src = $null
    foreach ($s in $have) { $c = Get-ExchangeCertSafe -Server $s -Thumbprint $thumb; if ($c -and "$($c.PrivateKeyExportable)" -eq 'True') { $src = $s; break } }
    if (-not $src) {
        throw ("Certificate $thumb is missing on $($need -join ', ') and cannot be copied: its private key is not exportable on $($have -join ', '). " +
            'Load the original PFX instead (button "Load last Let''s Encrypt/ACME certificate" on tab 2, or Browse).')
    }
    Write-Log "Will copy certificate $thumb from $src to $($need -join ', ')."
    Invoke-Step "Export-ExchangeCertificate -Server $src -Thumbprint $thumb -BinaryEncoded -Password <random>; Import-ExchangeCertificate on $($need -join ', ')" {
        $pw = New-RandomSecurePassword
        $exp = Export-ExchangeCertificate -Server $src -Thumbprint $thumb -BinaryEncoded -Password $pw -ErrorAction Stop
        $bytes = if ($exp -is [byte[]]) { $exp } else { [byte[]]$exp.FileData }
        if (-not $bytes -or $bytes.Length -lt 100) { throw "Export from $src returned no data." }
        foreach ($s in $need) {
            try {
                Import-ExchangeCertificate -Server $s -FileData $bytes -Password $pw -PrivateKeyExportable:$Exportable -ErrorAction Stop | Out-Null
                if (Get-ExchangeCertSafe -Server $s -Thumbprint $thumb) { Write-Log "${s}: certificate copied from $src." OK }
                else { Write-Log "${s}: import returned no error, but the certificate is not visible." ERROR }
            }
            catch { Write-Log "${s}: import FAILED: $($_.Exception.Message)" ERROR }
        }
    }
    if (-not (Test-DryRun)) { Update-Inventory }
}

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

    if (-not $script:State.PfxPath) {
        Copy-InstalledCertificate -Servers $servers -Exportable $exportable
        return
    }
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
    $popImap = [bool]$script:ui.PopImapCheck.IsChecked
    $services = @('IIS', 'SMTP') + @(if ($popImap) { 'POP', 'IMAP' })

    if (-not (Test-DryRun)) {
        $notImported = @($servers | Where-Object { -not (Get-ExchangeCertSafe -Server $_ -Thumbprint $thumb) })
        if ($notImported) { throw "Certificate is not imported on: $($notImported -join ', '). Run step A first." }
    }
    $msg = "Enable certificate $thumb for $($services -join ' + ') on: $($servers -join ', ')`n`n" +
    "- The HTTPS binding of the Default Web Site (443) switches to the new certificate immediately.`n" +
    "- The Exchange Back End site (444) is not touched.`n" +
    "- Internal transport certificate: $(if ($replaceInternal) { 'WILL BE REPLACED' } else { 'kept (restored if Exchange replaces it)' })`n" +
    $(if ($popImap) { "- POP3/IMAP4: X509CertificateName is set to a name on the certificate if needed, and the POP/IMAP services are restarted.`n" } else { '' }) +
    "- The old certificate stays on the servers. The current configuration is saved first (tab 3, Roll back)."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Enable certificate')) { Write-Log 'Enable cancelled.' WARN; return }
    try { Save-ChangeSnapshot -Before 'StepB' } catch { Write-Log "Could not save the rollback snapshot: $($_.Exception.Message)" WARN }

    foreach ($s in $servers) {
        try {
            $before = "$((Get-TransportService -Identity $s).InternalTransportCertificateThumbprint)"
            Write-Log "${s}: internal transport certificate before: $before"
            $popImapBefore = @()
            if ($popImap) { $cur = Get-ExchangeCertSafe -Server $s -Thumbprint $thumb; if ($cur) { $popImapBefore = @(Get-ServiceList $cur) } }
            $popImapNew = $popImap -and -not (($popImapBefore -contains 'POP') -and ($popImapBefore -contains 'IMAP'))
            Invoke-Step "Enable-ExchangeCertificate -Server $s -Thumbprint $thumb -Services $($services -join ',') -Force" {
                Enable-ExchangeCertificate -Server $s -Thumbprint $thumb -Services $services -Force -ErrorAction Stop
            }
            if ($popImap) { Set-PopImapCertificateName -Server $s -ServicesChanged $popImapNew }
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
        Write-Log 'Next: tab 3 Step C (SMTP connectors), then tab 4 (Verify).' INFO
    }
}

# POP3/IMAP4 pick their certificate by X509CertificateName: point it at a name on the new certificate, then restart.
function Set-PopImapCertificateName {
    param([string]$Server, [bool]$ServicesChanged = $true)   # ServicesChanged: the new certificate was just enabled for POP/IMAP
    $names = @($script:State.NewNames)
    $target = @($names | Where-Object { $_ -notmatch '\*' } | Select-Object -First 1)[0]
    if (-not $target) { $target = ($names | Select-Object -First 1) -replace '^\*\.', 'mail.' }
    $changed = $false
    foreach ($kind in 'Pop', 'Imap') {
        try { $cur = "$((& "Get-${kind}Settings" -Server $Server -ErrorAction Stop).X509CertificateName)" }
        catch { Write-Log "${Server}: Get-${kind}Settings failed: $($_.Exception.Message)" WARN; continue }
        if ($cur -and (Test-HostCovered -HostName $cur -CertNames $names)) { Write-Log "${Server}: ${kind} X509CertificateName $cur is on the new certificate." OK; continue }
        Write-Log "Rollback for ${Server} ${kind}: Set-${kind}Settings -Server $Server -X509CertificateName $(if ($cur) { $cur } else { '$null' })"
        Invoke-Step "Set-${kind}Settings -Server $Server -X509CertificateName $target" { & "Set-${kind}Settings" -Server $Server -X509CertificateName $target -ErrorAction Stop }
        $changed = $true
    }
    if (-not $changed -and -not $ServicesChanged) {
        Write-Log "${Server}: POP/IMAP already use the new certificate - services not restarted."
        return
    }
    $fqdn = Get-ServerFqdn $Server
    Invoke-Step "Restart the running POP3/IMAP4 services on $fqdn" {
        foreach ($svc in @(Get-Service -ComputerName $fqdn -Name MSExchangePOP3, MSExchangePOP3BE, MSExchangeIMAP4, MSExchangeIMAP4BE -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })) {
            try { $svc | Restart-Service -Force -ErrorAction Stop; Write-Log "${Server}: restarted $($svc.Name)." OK }
            catch { Write-Log "${Server}: could not restart $($svc.Name): $($_.Exception.Message)" WARN }
        }
    }
    if (-not $changed) { Write-Log "${Server}: POP/IMAP certificate names unchanged." }
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
            $pinnedNew = $false
            try {
                $pinnedNew = [bool](@(Get-ReceiveConnector -Server $s) | Where-Object {
                        (Test-FrontendConnector $_ '25') -and (Test-TlsNameMatches "$($_.TlsCertificateName)" $script:State.NewCert.Issuer $script:State.NewCert.Subject) })
            }
            catch { }
            if ($r.Thumbprint -eq $thumb) { & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'PASS' "Served new certificate ($($r.Protocol))" }
            elseif ($pinnedNew) {
                & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'FAIL' ("Served $($r.Thumbprint) ($($r.Subject)), but Default Frontend is pinned to the new certificate. Transport reloads connector settings after a few minutes - verify again; if it persists, restart MSExchangeFrontEndTransport in a quiet period.")
            }
            else {
                & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'INFO' ("Served $($r.Thumbprint) ($($r.Subject)). Default Frontend is not pinned to the new certificate, so Exchange offers the certificate matching the connector FQDN (usually self-signed). Use tab 3, Step C to pin the new certificate for internet senders.")
            }
        }
        catch { & $addRow $s "SMTP ${fqdn}:25 STARTTLS" 'INFO' "Could not probe: $($_.Exception.Message)" }

        # POP3S / IMAPS only when the new certificate is enabled for them (informational, like SMTP).
        foreach ($mp in @(@{ Svc = 'POP'; Port = 995; Cmd = 'Get-PopSettings' }, @{ Svc = 'IMAP'; Port = 993; Cmd = 'Get-ImapSettings' })) {
            if (-not $c -or (Get-ServiceList $c) -notcontains $mp.Svc) { continue }
            $check = "$($mp.Svc) ${fqdn}:$($mp.Port)"
            try {
                $r = Get-RemoteTlsCertificate -HostName $fqdn -Port $mp.Port -SniName $sni
                if ($r.Thumbprint -eq $thumb) { & $addRow $s $check 'PASS' "Served new certificate ($($r.Protocol))" }
                else { & $addRow $s $check 'FAIL' "Served $($r.Thumbprint) ($($r.Subject)) - check X509CertificateName ($($mp.Cmd)) and restart the service." }
            }
            catch { & $addRow $s $check 'INFO' "Could not probe (service stopped?): $($_.Exception.Message)" }
        }

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
            # Extended Protection (default since Exchange 2019 CU14 / SE) binds Windows authentication to the TLS
            # certificate: a load balancer that re-encrypts with a different certificate breaks Outlook/EWS sign-in.
            & $addRow '(endpoint)' "TLS ${h}:$p" $(if ($ok) { 'PASS' } else { 'FAIL' }) ("Served $($r.Thumbprint) ($($r.Subject))" + $(if (-not $ok) { ' - NOT the new certificate. A load balancer or reverse proxy that terminates TLS needs the new certificate too. With Extended Protection (on by default since Exchange 2019 CU14 / SE), a different certificate on the load balancer breaks Windows authentication for Outlook, EWS and ActiveSync.' } else { '' }))
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
    param([switch]$PassThru)
    Assert-Exchange; Assert-Validated
    $servers = Get-SelectedServers
    Update-Inventory
    $cands = @($script:State.Inventory | Where-Object { $servers -contains $_.Server -and $_.SelfSigned -ne 'True' -and $_.Thumbprint -ne $script:State.NewThumb })
    $conns = @(Get-ConnectorTlsReport -Servers $servers -NewIssuer $script:State.NewCert.Issuer -NewSubject $script:State.NewCert.Subject -OldCerts $cands)
    $rows = foreach ($c in $cands) {
        $blockers = @()
        if (-not $script:State.Verified[$c.Server]) { $blockers += 'server not verified on tab 4' }
        if ($c.Thumbprint -eq $script:State.AuthThumb) { $blockers += 'is the Auth certificate' }
        if (@($script:State.AuthOtherThumbs) -contains $c.Thumbprint) { $blockers += 'is the previous/next Auth certificate (Get-AuthConfig)' }
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
    if ($PassThru) { @($rows) }
}

function Invoke-RemoveOld {
    param([object[]]$Rows)   # rows from Update-OldCandidates (-Renew); default: the rows selected in the grid
    Assert-Exchange; Assert-Validated
    if ($Rows) { $targets = @($Rows | ForEach-Object { [pscustomobject]@{ Server = "$($_.Server)"; Thumbprint = "$($_.Thumbprint)"; Subject = "$($_.Subject)"; Blockers = "$($_.Blockers)" } }) }
    else {
        $sel = @($script:ui.OldGrid.SelectedItems)
        if (-not $sel) { throw 'Select one or more rows in the grid first.' }
        $targets = @(foreach ($rv in $sel) {
                [pscustomobject]@{ Server = "$($rv.Row['Server'])"; Thumbprint = "$($rv.Row['Thumbprint'])"; Subject = "$($rv.Row['Subject'])"; Blockers = "$($rv.Row['Blockers'])" }
            })
    }
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
# Auth (OAuth) certificate - tab 1
# ---------------------------------------------------------------------------------------------
# Copies the current Auth certificate to servers that miss it, or (fewer than 60 days left) creates a new one,
# makes it current (Set-AuthConfig) and restarts the services that cache it. Follows Microsoft's documented procedure.
function Invoke-AuthCertificate {
    Assert-Exchange
    $servers = @(Get-SelectedServers)
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    Update-Inventory
    # Without an answer from Get-AuthConfig, "no Auth certificate" is unknown, not a fact: never replace a working one.
    if (-not $script:State.AuthConfigRead) {
        throw 'Get-AuthConfig did not answer (see the log), so the current Auth certificate is unknown. Nothing was changed. Check the Exchange connection and try again.'
    }
    $thumb = $script:State.AuthThumb
    $have = @($script:State.Inventory | Where-Object { $thumb -and $_.Thumbprint -eq $thumb })
    $missing = @($servers | Where-Object { $_ -notin @($have | ForEach-Object { $_.Server }) })
    $days = if ($have) { ($have | Measure-Object DaysLeft -Minimum).Minimum } else { -1 }

    if ($have -and $days -ge 60) {
        if (-not $missing) { Write-Log "The Auth certificate is on all selected servers and valid for $days more days - nothing to do (it is renewed when fewer than 60 days are left)." OK; return }
        $msg = "Copy the Auth (OAuth) certificate $thumb to: $($missing -join ', ')?`n`nIt is exported from a server that has it (its private key must be exportable, which is the default for the Auth certificate)."
        if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
        if (-not (Confirm-Action $msg 'Copy Auth certificate')) { Write-Log 'Cancelled.' WARN; return }
        Copy-InstalledCertificate -Servers $servers -Thumbprint $thumb -Exportable $true
        return
    }

    $hybrid = [bool](Get-HybridConfigSafe)
    $offerUpload = {
        param([string]$When)
        Write-Log "Hybrid: Exchange Online needs the new Auth certificate $When (OAuth free/busy, MailTips, mailbox moves). Use ""Upload Auth certificate to Entra ID"" on tab 1, or rerun the Hybrid Configuration Wizard." WARN
        if (-not $script:Unattended -and (Confirm-Action "Upload the Auth certificates (current and next) to the dedicated Exchange hybrid app in Entra ID now?" 'Hybrid: upload Auth certificate')) { Invoke-UploadAuthToEntra }
    }

    # A rotation that is already scheduled: never create a second new certificate.
    $next = "$($script:State.AuthNextThumb)"; $nextDate = $script:State.AuthNextDate
    if ($next -and $next -ne $thumb -and $nextDate -and $nextDate -gt (Get-Date)) {
        Write-Log ('A new Auth certificate {0} is already scheduled: Exchange makes it current by itself on {1:yyyy-MM-dd HH:mm}. No new certificate is created.' -f $next, $nextDate) OK
        $nextMissing = @($servers | Where-Object { -not (Get-ExchangeCertSafe -Server $_ -Thumbprint $next) })
        if ($nextMissing) {
            $msg = "Copy the scheduled Auth certificate $next to: $($nextMissing -join ', ')?`n`nIt must be on every server before $($nextDate.ToString('yyyy-MM-dd HH:mm'))."
            if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
            if (Confirm-Action $msg 'Copy scheduled Auth certificate') { Copy-InstalledCertificate -Servers $servers -Thumbprint $next -Exportable $true }
        }
        if ($hybrid) { & $offerUpload "before $($nextDate.ToString('yyyy-MM-dd HH:mm'))" }
        return
    }

    # Microsoft's rotation: stage the new certificate as "next", effective in 49 hours; the AuthAdmin servicelet
    # (MSExchangeServiceHost, every 12 hours) makes it current on that date. Only when the current one is expired,
    # missing or about to expire is it replaced immediately.
    $schedule = [bool]($have -and -not $missing -and $days -ge 3)
    $effective = (Get-Date).AddHours(49)
    $src = $servers[0]
    $notSelected = @($script:State.Servers.Keys | Where-Object { $_ -notin $servers })
    $current = "Current Auth certificate: $(if ($thumb) { "$thumb ($days days left)" } else { 'none' })$(if ($missing -and $have) { "; missing on $($missing -join ', ')" })"
    if ($schedule) {
        $msg = "Schedule a new Auth (OAuth) certificate (Microsoft's rotation procedure):`n`n" +
        "1. New-ExchangeCertificate on $src (self-signed, exportable key)`n" +
        "2. Copy it to: $($servers -join ', ')`n" +
        "3. Set-AuthConfig -NewCertificateThumbprint <new> -NewCertificateEffectiveDate $($effective.ToString('yyyy-MM-dd HH:mm')) (in 49 hours)`n`n" +
        "Nothing changes for users now. Exchange makes the new certificate current by itself on that date (event 2014, MSExchange AuthAdmin). $current"
        if ($hybrid) { $msg += "`n`nHybrid: afterwards the tool offers to upload the current and the new certificate to Entra ID - before the switch, so OAuth keeps working." }
    }
    else {
        $msg = "Create a new Auth (OAuth) certificate and make it the current one NOW (the current one is expired, missing or expires in less than 3 days, so the 49-hour rotation is not possible):`n`n" +
        "1. New-ExchangeCertificate on $src (self-signed, exportable key)`n" +
        "2. Copy it to: $($servers -join ', ')`n" +
        "3. Set-AuthConfig -NewCertificateThumbprint <new> -NewCertificateEffectiveDate <now>, then -PublishCertificate and -ClearPreviousCertificate`n" +
        "4. Restart MSExchangeServiceHost and recycle the OWA and ECP app pools on each server`n`n$current"
        if ($hybrid) { $msg += "`n`nHybrid: OAuth to Exchange Online fails until the new certificate is uploaded - the tool offers to do it right afterwards." }
    }
    if ($notSelected) { $msg += "`n`nWARNING: not selected on tab 1: $($notSelected -join ', '). Every Exchange server needs the Auth certificate - select them all first." }
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg $(if ($schedule) { 'Schedule new Auth certificate' } else { 'Replace Auth certificate now' }))) { Write-Log 'Cancelled.' WARN; return }

    $new = Invoke-Step "New-ExchangeCertificate -Server $src -KeySize 2048 -PrivateKeyExportable `$true -SubjectName 'cn=Microsoft Exchange Server Auth Certificate' -FriendlyName 'Microsoft Exchange Server Auth Certificate' -DomainName @() -Services None" {
        New-ExchangeCertificate -Server $src -KeySize 2048 -PrivateKeyExportable $true -SubjectName 'cn=Microsoft Exchange Server Auth Certificate' `
            -FriendlyName 'Microsoft Exchange Server Auth Certificate' -DomainName @() -Services None -ErrorAction Stop
    }
    if (Test-DryRun) {
        Write-Log "[DRY RUN] copy the new certificate to $($servers -join ', ') (Export-ExchangeCertificate / Import-ExchangeCertificate)" CMD
        if ($schedule) {
            Write-Log "[DRY RUN] Set-AuthConfig -NewCertificateThumbprint <new> -NewCertificateEffectiveDate '$($effective.ToString('yyyy-MM-dd HH:mm'))'   (Exchange switches by itself; no publish, no restarts)" CMD
        }
        else {
            Write-Log '[DRY RUN] Set-AuthConfig -NewCertificateThumbprint <new> -NewCertificateEffectiveDate (Get-Date) -Force; Set-AuthConfig -PublishCertificate; Set-AuthConfig -ClearPreviousCertificate' CMD
            Write-Log '[DRY RUN] restart MSExchangeServiceHost and recycle MSExchangeOWAAppPool / MSExchangeECPAppPool on each server' CMD
        }
        if ($hybrid) { Write-Log '[DRY RUN] then offer: Upload Auth certificate to Entra ID (current + next)' CMD }
        return
    }
    $newThumb = "$(@($new | Where-Object { $_.Thumbprint })[0].Thumbprint)"
    if (-not $newThumb) { throw 'New-ExchangeCertificate returned no thumbprint.' }
    Write-Log "New Auth certificate $newThumb created on $src." OK
    Copy-InstalledCertificate -Servers $servers -Thumbprint $newThumb -Exportable $true
    $missingNew = @($servers | Where-Object { -not (Get-ExchangeCertSafe -Server $_ -Thumbprint $newThumb) })
    if ($missingNew) { throw "The new Auth certificate $newThumb is not on $($missingNew -join ', ') - Set-AuthConfig was NOT changed. Fix the copy (see the log), then use the button again." }

    if ($schedule) {
        Invoke-Step "Set-AuthConfig -NewCertificateThumbprint $newThumb -NewCertificateEffectiveDate '$($effective.ToString('yyyy-MM-dd HH:mm'))'" {
            Set-AuthConfig -NewCertificateThumbprint $newThumb -NewCertificateEffectiveDate $effective -Confirm:$false -ErrorAction Stop
        }
        $ac = Get-AuthConfig
        if ("$($ac.NextCertificateThumbprint)" -eq $newThumb -and "$($ac.CurrentCertificateThumbprint)" -eq $thumb) {
            Write-Log ('Scheduled: {0} becomes the current Auth certificate on {1:yyyy-MM-dd HH:mm}; until then {2} stays current. The AuthAdmin servicelet switches within 12 hours after that time (Application log: MSExchange AuthAdmin, event 2014).' -f $newThumb, $effective, $thumb) OK
            Write-Log 'After the switch, recycle the OWA and ECP app pools on each server (Restart-WebAppPool MSExchangeOWAAppPool; Restart-WebAppPool MSExchangeECPAppPool). The inventory on tab 1 warns if the switch did not happen.'
        }
        else { Write-Log "Get-AuthConfig shows current $($ac.CurrentCertificateThumbprint) / next $($ac.NextCertificateThumbprint), expected current $thumb / next $newThumb - check it manually." ERROR }
        Update-Inventory
        if ($hybrid) { & $offerUpload "before $($effective.ToString('yyyy-MM-dd HH:mm'))" }
        return
    }

    if ($thumb) { Write-Log "Rollback (the old certificate stays installed): Set-AuthConfig -NewCertificateThumbprint $thumb -NewCertificateEffectiveDate (Get-Date) -Force; Set-AuthConfig -PublishCertificate" }
    $force = @{}
    if ((Get-Command Set-AuthConfig).Parameters.ContainsKey('Force')) { $force.Force = $true }
    Invoke-Step "Set-AuthConfig -NewCertificateThumbprint $newThumb -NewCertificateEffectiveDate (Get-Date) -Force" {
        Set-AuthConfig -NewCertificateThumbprint $newThumb -NewCertificateEffectiveDate (Get-Date) -Confirm:$false @force -ErrorAction Stop
    }
    Invoke-Step 'Set-AuthConfig -PublishCertificate' { Set-AuthConfig -PublishCertificate -Confirm:$false -ErrorAction Stop }
    Invoke-Step 'Set-AuthConfig -ClearPreviousCertificate' { Set-AuthConfig -ClearPreviousCertificate -Confirm:$false -ErrorAction Stop }
    $now = "$((Get-AuthConfig).CurrentCertificateThumbprint)"
    if ($now -eq $newThumb) { Write-Log "The Auth certificate is now $newThumb." OK } else { Write-Log "Get-AuthConfig shows $now, expected $newThumb - check it manually." ERROR }

    foreach ($s in $servers) {
        $fqdn = Get-ServerFqdn $s
        try {
            Invoke-Step "Invoke-Command -ComputerName $fqdn { Restart-Service MSExchangeServiceHost; recycle MSExchangeOWAAppPool, MSExchangeECPAppPool }" {
                Invoke-Command -ComputerName $fqdn -ErrorAction Stop -ScriptBlock {
                    Restart-Service -Name MSExchangeServiceHost -Force -ErrorAction Stop
                    Import-Module WebAdministration -ErrorAction Stop
                    foreach ($pool in 'MSExchangeOWAAppPool', 'MSExchangeECPAppPool') { try { Restart-WebAppPool -Name $pool -ErrorAction Stop } catch { Start-WebAppPool -Name $pool -ErrorAction Stop } }
                }
                Write-Log "${s}: MSExchangeServiceHost restarted, OWA/ECP app pools recycled." OK
            }
        }
        catch { Write-Log "${s}: restart failed ($($_.Exception.Message)). On the server run: Restart-Service MSExchangeServiceHost; Restart-WebAppPool MSExchangeOWAAppPool; Restart-WebAppPool MSExchangeECPAppPool" WARN }
    }
    Update-Inventory
    if ($hybrid) { & $offerUpload 'now' }
}

# ---------------------------------------------------------------------------------------------
# Auth certificate -> dedicated Exchange hybrid app in Entra ID - tab 1
# Uses Microsoft's ConfigureExchangeHybridApplication.ps1 (CSS-Exchange), only with a valid Microsoft signature.
# It asks Y/N questions and refuses to run next to ExchangeOnlineManagement, so it runs in its own console window,
# in "File" mode with public-only .cer files (no Exchange Management Shell or private key needed there).
# ---------------------------------------------------------------------------------------------
$script:HybridAppScriptUrl = 'https://github.com/microsoft/CSS-Exchange/releases/latest/download/ConfigureExchangeHybridApplication.ps1'
$script:HybridAppScriptPath = Join-Path $env:LOCALAPPDATA 'ExchangeCertTool\ConfigureExchangeHybridApplication.ps1'

function Test-MicrosoftSignature {
    param([Parameter(Mandatory)][string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = "$($sig.SignerCertificate.Subject)"
    [pscustomobject]@{ Ok = ("$($sig.Status)" -eq 'Valid' -and $subject -match '(^|,\s*)O=Microsoft Corporation(\s*,|$)'); Status = "$($sig.Status)"; Signer = $subject }
}

function Get-HybridAppScript {
    $path = $script:HybridAppScriptPath
    $fresh = (Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).LastWriteTime -gt (Get-Date).AddDays(-7))
    if (-not $fresh) {
        New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
        $tmp = "$path.download"
        Write-Log "Downloading $($script:HybridAppScriptUrl)"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $script:HybridAppScriptUrl -OutFile $tmp -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $path -Force
    }
    $sig = Test-MicrosoftSignature -Path $path
    if (-not $sig.Ok) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw "ConfigureExchangeHybridApplication.ps1 does not have a valid Microsoft signature (status: $($sig.Status), signer: $($sig.Signer)). It was deleted and NOT run."
    }
    Write-Log "ConfigureExchangeHybridApplication.ps1: Microsoft signature valid ($($sig.Signer -replace ',.*$', ''))." OK
    $path
}

# Public part of an installed Exchange certificate as DER bytes, from the first server that has it.
function Get-ExchangeCertPublicBytes {
    param([Parameter(Mandatory)][string]$Thumbprint, [string[]]$Servers)
    foreach ($s in $Servers) {
        $x = ConvertTo-X509 (Get-ExchangeCertSafe -Server $s -Thumbprint $Thumbprint)
        if ($x) { return , [byte[]]$x.RawData }
    }
    $null
}

function Invoke-UploadAuthToEntra {
    Assert-Exchange
    $ac = Get-AuthConfig -ErrorAction Stop
    $certs = [ordered]@{}
    if ("$($ac.CurrentCertificateThumbprint)") { $certs['current'] = "$($ac.CurrentCertificateThumbprint)" }
    if ("$($ac.NextCertificateThumbprint)" -and "$($ac.NextCertificateThumbprint)" -ne "$($ac.CurrentCertificateThumbprint)") { $certs['next'] = "$($ac.NextCertificateThumbprint)" }
    if (-not $certs.Count) { throw 'Get-AuthConfig shows no Auth certificate. Create one first with "Renew / copy Auth certificate".' }
    $servers = @(Get-SelectedServers) + @($script:State.Servers.Keys | Where-Object { $_ -notin @(Get-SelectedServers) })
    # The dedicated hybrid app is in use when the evoSTS auth server has an application identifier.
    $dedicated = $null
    try { $dedicated = [bool](@(Get-AuthServer -ErrorAction Stop | Where-Object { "$($_.Name)" -like '*evoSTS*' -and "$($_.ApplicationIdentifier)" })) } catch { }
    $dir = Join-Path (Split-Path $script:LogFile) ('AuthCertUpload_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
    $files = [ordered]@{}
    foreach ($k in $certs.Keys) { $files[$k] = Join-Path $dir ("auth-$k-$($certs[$k]).cer") }
    $q = { param([string]$s) "'" + ($s -replace "'", "''") + "'" }
    $cmds = @($files.Values | ForEach-Object { "& $(& $q '<script>') -UpdateCertificate -CertificateMethod File -CertificateInformation $(& $q $_)" })
    $msg = "Upload the Auth certificate to the dedicated Exchange hybrid app in Entra ID (ExchangeServerApp-<organization GUID>)?`n`n" +
    "$(($certs.Keys | ForEach-Object { "  $($_): $($certs[$_])" }) -join "`n")`n`n" +
    "The tool exports the public certificates (no private key) to $dir, downloads Microsoft's ConfigureExchangeHybridApplication.ps1 (runs only with a valid Microsoft signature) and opens it in a new PowerShell window:`n  $($cmds -join "`n  ")`n`n" +
    'Sign in there with a Global Administrator or Application Administrator and answer its questions. The script also removes expired certificates from the app.'
    if ($dedicated -eq $false) { $msg += "`n`nNOTE: Get-AuthServer shows no dedicated hybrid app (evoSTS has no ApplicationIdentifier). If your hybrid still uses the shared Exchange Online service principal, rerun the Hybrid Configuration Wizard instead - the script will report that the app does not exist." }
    elseif ($null -eq $dedicated) { $msg += "`n`nNOTE: Get-AuthServer could not be read, so it is unknown whether the dedicated hybrid app is in use." }
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be exported, downloaded or run)" }
    if (-not (Confirm-Action $msg 'Upload Auth certificate to Entra ID')) { Write-Log 'Cancelled.' WARN; return }
    if (Test-DryRun) {
        foreach ($k in $certs.Keys) { Write-Log "[DRY RUN] export the public $k Auth certificate $($certs[$k]) to $($files[$k])" CMD }
        Write-Log "[DRY RUN] download and signature-check $($script:HybridAppScriptUrl)" CMD
        foreach ($c in $cmds) { Write-Log "[DRY RUN] (new PowerShell window) $c" CMD }
        return
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    foreach ($k in $certs.Keys) {
        $bytes = Get-ExchangeCertPublicBytes -Thumbprint $certs[$k] -Servers $servers
        if (-not $bytes) { throw "The $k Auth certificate $($certs[$k]) was not found on $($servers -join ', ') - nothing was uploaded. Use ""Renew / copy Auth certificate"" first." }
        [IO.File]::WriteAllBytes($files[$k], $bytes)
        Write-Log "Exported the public $k Auth certificate to $($files[$k])." OK
    }
    $script = Get-HybridAppScript
    $body = (($files.Values | ForEach-Object { "& $(& $q $script) -UpdateCertificate -CertificateMethod File -CertificateInformation $(& $q $_)" }) -join "`n") +
    "`nWrite-Host ''; Write-Host 'Finished. Check the output above, then close this window.' -ForegroundColor Cyan"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    Write-Log "Starting a new PowerShell window: $($body -replace "`n", ' ; ')" CMD
    Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) | Out-Null
    Write-Log 'Sign in and answer the questions in the new window. Afterwards test, for example: Test-OAuthConnectivity -Service EWS -TargetUri https://outlook.office365.com/ews/exchange.asmx -Mailbox <on-premises mailbox>' OK
}

# ---------------------------------------------------------------------------------------------
# Certificate request (CSR) for a commercial or internal CA - tab 2
# ---------------------------------------------------------------------------------------------
function New-CertificateRequest {
    Assert-Exchange
    $servers = @(Get-SelectedServers)
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    $src = $servers[0]
    $names = @(Get-LeNames -AllowInternal)
    $subject = "CN=$($names[0])"
    $friendly = 'Exchange {0} {1:yyyy-MM-dd}' -f $names[0], (Get-Date)
    $cmd = "New-ExchangeCertificate -Server $src -GenerateRequest -SubjectName '$subject' -DomainName $($names -join ',') -KeySize 2048 -PrivateKeyExportable `$true -FriendlyName '$friendly'"
    $msg = "Create a certificate request (CSR) on $src for:`n  $($names -join "`n  ")`n`nThe private key is created on $src and marked exportable, so Step A can copy the issued certificate to the other servers. The names come from the list on tab 1b."
    if (Test-DryRun) { Write-Log "[DRY RUN] $cmd" CMD; Write-Log '[DRY RUN] the request would be saved to a .req file you choose.' CMD; return }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = 'Certificate request (*.req)|*.req|All files (*.*)|*.*'
    $dlg.FileName = ($names[0] -replace '^\*\.', 'wildcard.') + '.req'
    if (-not $dlg.ShowDialog($script:Window)) { return }
    if (-not (Confirm-Action $msg 'Create CSR')) { Write-Log 'Cancelled.' WARN; return }
    $req = Invoke-Step $cmd {
        New-ExchangeCertificate -Server $src -GenerateRequest -SubjectName $subject -DomainName $names -KeySize 2048 -PrivateKeyExportable $true -FriendlyName $friendly -ErrorAction Stop
    }
    $req = (@($req | Where-Object { $_ }) | ForEach-Object { "$_" }) -join "`r`n"
    if (-not $req) { throw 'New-ExchangeCertificate returned no request text.' }
    [IO.File]::WriteAllText($dlg.FileName, $req, [Text.Encoding]::ASCII)
    Write-Log "CSR saved to $($dlg.FileName). Submit it to your CA (DigiCert, Sectigo, GlobalSign ...). Internal AD CS: certreq -submit -attrib ""CertificateTemplate:WebServer"" ""$($dlg.FileName)"" ""$([IO.Path]::ChangeExtension($dlg.FileName, '.cer'))"". Then click ""Complete pending request""." OK
}

# Imports the issued certificate on the server that holds the matching pending request, then uses it as the new certificate.
function Complete-CertificateRequest {
    param([string]$Path)   # issued certificate file; default: ask with a file dialog
    Assert-Exchange
    $servers = @(Get-SelectedServers)
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    if (-not $Path) {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Issued certificate (*.cer;*.crt;*.p7b;*.pem)|*.cer;*.crt;*.p7b;*.pem|All files (*.*)|*.*'
        if (-not $dlg.ShowDialog($script:Window)) { return }
        $Path = $dlg.FileName
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    $type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($bytes)
    # Opening a PFX here could store its private key on this machine - PFX files go through Browse instead.
    if ("$type" -in 'Pfx', 'Pkcs12') { throw 'This is a PFX file (with private key). Use "Browse..." for PFX files.' }
    $coll = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $coll.Import($bytes)
    $leaf = @($coll | Where-Object { $c = $_; -not ($coll | Where-Object { $_.Thumbprint -ne $c.Thumbprint -and $_.Issuer -eq $c.Subject }) }) | Select-Object -First 1
    if (-not $leaf) { throw 'No certificate found in the file.' }
    $cn = $leaf.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    Write-Log "Issued certificate: $($leaf.Subject), issuer $($leaf.Issuer), thumbprint $($leaf.Thumbprint), expires $($leaf.NotAfter.ToString('yyyy-MM-dd'))."
    # Pair the certificate with its request by PUBLIC KEY: only the server holding that request has the private key.
    # Matching by name alone can import it on a server without the key (a second CSR for the same name elsewhere).
    $leafKey = ConvertTo-HexString (Get-CertSpki $leaf)
    $all = @(foreach ($s in $servers) {
            foreach ($p in @(Get-ExchangeCertificate -Server $s | Where-Object { "$($_.Status)" -eq 'PendingRequest' })) {
                $pcn = if ("$($p.Subject)" -match '(?:^|,\s*)CN=([^,]+)') { $Matches[1].Trim() } else { '' }
                [pscustomobject]@{ Server = $s; Thumbprint = "$($p.Thumbprint)"; Cn = $pcn; Key = (Get-PendingRequestKey $p) }
            }
        })
    $byKey = @($all | Where-Object { $_.Key -and $_.Key -eq $leafKey })
    if ($byKey) {
        $pending = @($byKey | Select-Object -First 1)
        Write-Log "Matched by public key: the request on $($pending[0].Server) belongs to this certificate." OK
    }
    else {
        $unknown = @($all | Where-Object { -not $_.Key -and $_.Cn -eq $cn })
        $sameCnKnown = @($all | Where-Object { $_.Key -and $_.Cn -eq $cn })
        if (-not $unknown) {
            if ($sameCnKnown) { throw "The pending request(s) for CN=$cn on $(($sameCnKnown | ForEach-Object { $_.Server } | Select-Object -Unique) -join ', ') have a different public key: this certificate was issued for a CSR made elsewhere (another server, or a request that was removed). Nothing was imported." }
            throw "No pending request for CN=$cn was found on $($servers -join ', '). Select the server where you created the CSR on tab 1."
        }
        $srvs = @($unknown | ForEach-Object { $_.Server } | Select-Object -Unique)
        if ($srvs.Count -gt 1) { throw "Pending requests for CN=$cn exist on $($srvs -join ', ') and their public keys cannot be read, so the tool cannot tell which one this certificate belongs to. Select only the server where you created this CSR on tab 1 (or remove the extra request with Remove-ExchangeCertificate). Nothing was imported." }
        $pending = @($unknown | Select-Object -First 1)
        Write-Log "The public key of the pending request on $($srvs[0]) could not be read - matched by name (CN=$cn) only." WARN
    }
    $msg = "Import $Path`n  $($leaf.Subject)`n`ninto the pending request on: $($pending[0].Server)"
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Complete pending request')) { Write-Log 'Cancelled.' WARN; return }
    $done = $null
    $s = $pending[0].Server
    $existed = [bool](Get-ExchangeCertSafe -Server $s -Thumbprint $leaf.Thumbprint)
    try {
        Invoke-Step "Import-ExchangeCertificate -Server $s -FileData <$($bytes.Length) bytes of $Path>" {
            Import-ExchangeCertificate -Server $s -FileData $bytes -ErrorAction Stop | Out-Null
        }
        if (-not (Test-DryRun)) {
            $ex = Get-ExchangeCertSafe -Server $s -Thumbprint $leaf.Thumbprint
            if ($ex -and "$($ex.HasPrivateKey)" -ne 'False') { $done = $s; Write-Log "${s}: request completed - certificate $($leaf.Thumbprint) installed with its private key." OK }
            else {
                Write-Log "${s}: the certificate was imported but has no private key here - it does not belong to this server's request." ERROR
                if ($ex -and -not $existed) {
                    # Do not leave a key-less copy behind (it would be offered in the installed list and fail later).
                    Invoke-Step "Remove-ExchangeCertificate -Server $s -Thumbprint $($leaf.Thumbprint) -Confirm:`$false   # key-less copy" {
                        Remove-ExchangeCertificate -Server $s -Thumbprint $leaf.Thumbprint -Confirm:$false -ErrorAction Stop
                    }
                    Write-Log "${s}: removed the copy without a private key again." OK
                }
            }
        }
    }
    catch { Write-Log "${s}: import FAILED: $($_.Exception.Message)" ERROR }
    if (Test-DryRun) { return }
    if (-not $done) { throw 'The certificate could not be paired with a pending request (see the log).' }
    Write-Log 'If the CA sent an intermediate certificate, it must be in the Intermediate Certification Authorities store of every server (the chain check in tab 2 shows it).'
    Update-InventoryAndInstalled
    $idx = -1
    for ($k = 0; $k -lt @($script:InstalledChoices).Count; $k++) { if ($script:InstalledChoices[$k].Thumbprint -eq $leaf.Thumbprint) { $idx = $k } }
    if ($idx -lt 0) { throw "Certificate $($leaf.Thumbprint) is installed on $done but not in the installed list - pick it under ""Or installed""." }
    $script:ui.InstalledCertCombo.SelectedIndex = $idx
    Invoke-UseInstalledCertificate
}

# ---------------------------------------------------------------------------------------------
# Step D: Exchange Online hybrid connectors - tab 3 (optional, ExchangeOnlineManagement module)
# Exchange Online checks the on-premises certificate by NAME only: inbound connector TlsSenderCertificateName,
# outbound connector TlsDomain. A renewal with the same names needs no change there; this step only fixes names
# that the new certificate no longer covers. EXO cmdlets get the prefix "Cloud" so they cannot clash with on-premises.
# ---------------------------------------------------------------------------------------------
$script:ExoPrefix = 'Cloud'

function Test-ExoConnected { [bool](Get-Command "Get-$($script:ExoPrefix)InboundConnector" -ErrorAction SilentlyContinue) }

# Loads ExchangeOnlineManagement; offers to install it from the PowerShell Gallery when it is missing.
function Import-ExoModule {
    if (Get-Module ExchangeOnlineManagement) { return }
    $psd = Find-ModuleManifest 'ExchangeOnlineManagement'
    if (-not $psd) {
        Write-Log "ExchangeOnlineManagement not found for $env:USERDOMAIN\$env:USERNAME. Searched:" WARN
        foreach ($r in Get-ModuleSearchRoots) { Write-Log ("    {0}  {1}" -f $(if (Test-Path -LiteralPath $r) { '[exists] ' } else { '[missing]' }), $r) }
        $manual = 'In Windows PowerShell (powershell.exe) run:  Install-Module ExchangeOnlineManagement -Scope CurrentUser'
        if ($script:Unattended) { throw "The ExchangeOnlineManagement module is not installed. $manual" }
        $msg = "Step D needs Microsoft's ExchangeOnlineManagement module, which is not installed for $env:USERNAME on $env:COMPUTERNAME.`n`n" +
        "Install it now from the PowerShell Gallery?`n  Install-Module ExchangeOnlineManagement -Scope CurrentUser`n`n" +
        'This only installs a module on this computer and changes nothing in Exchange, so it also runs with Dry run on. Needs internet access to www.powershellgallery.com.'
        if (-not (Confirm-Action $msg 'Install ExchangeOnlineManagement')) { throw "The ExchangeOnlineManagement module is not installed. $manual - then click the button again." }
        Install-GalleryModule -Name 'ExchangeOnlineManagement'
        $psd = Find-ModuleManifest 'ExchangeOnlineManagement'
        if (-not $psd) { throw 'Install-Module finished, but ExchangeOnlineManagement was not found in the module folders (see the log).' }
    }
    try { Import-Module $psd -ErrorAction Stop }
    catch { throw "ExchangeOnlineManagement was found at $psd but could not be loaded: $($_.Exception.Message)  [If the files were copied from another machine, run: Get-ChildItem '$(Split-Path $psd)' -Recurse | Unblock-File]" }
    Write-Log "Loaded ExchangeOnlineManagement $((Get-Module ExchangeOnlineManagement).Version) from $psd." OK
}

# Installs a module for the current user from the PowerShell Gallery (Windows PowerShell 5.1: TLS 1.2 + NuGet provider first).
function Install-GalleryModule {
    param([Parameter(Mandatory)][string]$Name)
    Write-Log "Install-Module $Name -Scope CurrentUser -Repository PSGallery" CMD
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' }
    if (-not $nuget) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null }
    Install-Module $Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
    $installed = @(Get-InstalledModule $Name -ErrorAction SilentlyContinue | Select-Object -First 1)
    Write-Log "$Name installed$(if ($installed) { ": $($installed[0].Version) in $($installed[0].InstalledLocation)" })." OK
}

function Connect-ExoSession {
    if (Test-ExoConnected) { return }
    if ($script:Unattended) { throw 'Exchange Online needs an interactive sign-in - not available in an unattended run.' }
    Import-ExoModule
    Write-Log 'Connecting to Exchange Online - sign in with an Exchange administrator of the tenant (read-only until you click Step D with Dry run off).'
    Connect-ExchangeOnline -Prefix $script:ExoPrefix -ShowBanner:$false -ErrorAction Stop
    if (-not (Test-ExoConnected)) { throw 'Connected, but the connector cmdlets are not available - the account needs an Exchange administrator role in Exchange Online.' }
    $script:ExoConnectedByTool = $true
    Write-Log 'Connected to Exchange Online.' OK
}

function Invoke-Exo { param([string]$Verb, [string]$Noun, [hashtable]$Params = @{}) & "$Verb-$($script:ExoPrefix)$Noun" @Params -ErrorAction Stop }

# Does a connector name value match the certificate names, the way Exchange Online compares them?
# Inbound (TlsSenderCertificateName): exact name, or "*.domain" = any certificate name in that domain.
# Outbound (TlsDomain): host name checked like a TLS client does (a *.domain certificate covers one label).
function Test-ExoNameCovered {
    param([string]$Value, [string[]]$Names, [ValidateSet('Inbound', 'Outbound')][string]$Kind)
    $v = "$Value".Trim().ToLowerInvariant()
    $n = @($Names | ForEach-Object { "$_".ToLowerInvariant() })
    if (-not $v) { return $true }
    if ($n -contains $v) { return $true }
    if ($v.StartsWith('*.')) { $suffix = $v.Substring(1); return [bool]@($n | Where-Object { $_.EndsWith($suffix) }) }
    if ($Kind -eq 'Outbound') { return (Test-HostCovered -HostName $v -CertNames $n) }
    $false
}

# The value the HCW sets: the subject CN of the certificate (e.g. mail.contoso.com or *.contoso.com).
function Get-CertTlsDomain {
    param([string]$Subject, [string[]]$Names)
    if ("$Subject" -match '(?:^|,\s*)CN=([^,]+)') { return $Matches[1].Trim().ToLowerInvariant() }
    "$(@($Names)[0])".ToLowerInvariant()
}

# One row per on-premises connector in Exchange Online. Action: UPDATE / OK / SKIP.
function Get-ExoConnectorPlan {
    param([object[]]$Inbound, [object[]]$Outbound, [string[]]$Names, [string]$Subject, [string[]]$OwnNames)
    $target = Get-CertTlsDomain -Subject $Subject -Names $Names
    $rows = New-Object System.Collections.Generic.List[object]
    $own = { param($v, $c) "$($c.ConnectorSource)" -eq 'HybridWizard' -or (Test-ExoNameCovered -Value $v -Names $OwnNames -Kind Outbound) -or (Test-ExoNameCovered -Value $v -Names $OwnNames -Kind Inbound) }
    foreach ($c in @($Inbound | Where-Object { $_ -and "$($_.ConnectorType)" -eq 'OnPremises' })) {
        $v = "$($c.TlsSenderCertificateName)"
        $row = [pscustomobject]@{ Action = 'OK'; Type = 'Inbound'; Connector = "$($c.Identity)"; Setting = 'TlsSenderCertificateName'; Current = $v; New = ''; Note = '' }
        if (-not $v) { $row.Action = 'SKIP'; $row.Note = 'No certificate name set (identified by IP address) - not affected.' }
        elseif (Test-ExoNameCovered -Value $v -Names $Names -Kind Inbound) { $row.Note = 'Matches the new certificate - no change needed.' }
        elseif (-not (& $own $v $c)) { $row.Action = 'SKIP'; $row.Note = 'Not created by the HCW and not one of the Exchange certificates - left alone.' }
        else { $row.Action = 'UPDATE'; $row.New = $target; $row.Note = 'The new certificate does not have this name - mail from on-premises would be rejected.' }
        $rows.Add($row)
    }
    foreach ($c in @($Outbound | Where-Object { $_ -and "$($_.ConnectorType)" -eq 'OnPremises' })) {
        $v = "$($c.TlsDomain)"
        $row = [pscustomobject]@{ Action = 'OK'; Type = 'Outbound'; Connector = "$($c.Identity)"; Setting = 'TlsDomain'; Current = $v; New = ''; Note = '' }
        if ("$($c.TlsSettings)" -ne 'DomainValidation' -or -not $v) { $row.Action = 'SKIP'; $row.Note = "TlsSettings = $(if ("$($c.TlsSettings)") { $c.TlsSettings } else { 'none' }) - the certificate name is not checked." }
        elseif (Test-ExoNameCovered -Value $v -Names $Names -Kind Outbound) { $row.Note = 'Covered by the new certificate - no change needed.' }
        elseif (-not (& $own $v $c)) { $row.Action = 'SKIP'; $row.Note = 'Not created by the HCW and not one of the Exchange certificates - left alone.' }
        else { $row.Action = 'UPDATE'; $row.New = $target; $row.Note = 'Not covered by the new certificate - mail from Exchange Online to on-premises would fail.' }
        $rows.Add($row)
    }
    $rows.ToArray()   # unrolled on purpose: callers use @(...)
}

# Names of the CA certificates the selected servers use for SMTP now (to recognise connectors that belong to Exchange).
function Get-OwnSmtpNames {
    @($script:State.Inventory | Where-Object { $_.SelfSigned -ne 'True' -and ($_.Services -split '\s*,\s*') -contains 'SMTP' } |
        ForEach-Object { "$($_.Domains)" -split '\s*,\s*' } | Where-Object { $_ } | Select-Object -Unique)
}

function Get-ExoConnectorPlanLive {
    Assert-Validated
    Connect-ExoSession
    if (-not $script:State.Inventory) { Update-Inventory }
    $in = @(Invoke-Exo Get InboundConnector); $out = @(Invoke-Exo Get OutboundConnector)
    $plan = Get-ExoConnectorPlan -Inbound $in -Outbound $out -Names @($script:State.NewNames) -Subject "$($script:State.NewCert.Subject)" -OwnNames (Get-OwnSmtpNames)
    $script:ui.ExoGrid.ItemsSource = (ConvertTo-DataTable $plan @('Action', 'Type', 'Connector', 'Setting', 'Current', 'New', 'Note')).DefaultView
    if (-not $plan) { Write-Log 'Exchange Online: no on-premises (hybrid) connectors found.' OK }
    foreach ($r in $plan) { Write-Log ("Exchange Online {0} connector '{1}': {2} = {3} -> {4}{5}" -f $r.Type, $r.Connector, $r.Setting, $(if ($r.Current) { $r.Current } else { '(empty)' }), $r.Action, $(if ($r.New) { " ($($r.New))" } else { '' })) $(if ($r.Action -eq 'UPDATE') { 'WARN' } else { 'INFO' }) }
    $plan
}

function Invoke-UpdateExoConnectors {
    $plan = @(Get-ExoConnectorPlanLive)
    $todo = @($plan | Where-Object { $_.Action -eq 'UPDATE' })
    if (-not $todo) { Write-Log 'Exchange Online: nothing to change - the hybrid connectors match the new certificate.' OK; return }
    $msg = "Change these Exchange Online connectors?`n`n$(($todo | ForEach-Object { "  $($_.Type) '$($_.Connector)': $($_.Setting) $($_.Current) -> $($_.New)" }) -join "`n")`n`n" +
    'Do this right after Step C (when Exchange on-premises presents the new certificate): with the new name, Exchange Online no longer accepts the old certificate. The current values are saved to a snapshot; "Roll back from snapshot" restores them.'
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Step D: Exchange Online connectors')) { Write-Log 'Cancelled.' WARN; return }
    $snap = [ordered]@{ Version = 2; Created = (Get-Date).ToString('s'); Before = 'StepD'; NewThumbprint = $script:State.NewThumb; Servers = [ordered]@{}; Connectors = @()
        CloudConnectors = @($plan | Where-Object { $_.Action -ne 'SKIP' } | ForEach-Object { [ordered]@{ Type = $_.Type; Identity = $_.Connector; Setting = $_.Setting; Value = $_.Current } }) }
    $path = Join-Path (Split-Path $script:LogFile) ('Snapshot_{0:yyyyMMdd_HHmmss}_before-StepD.json' -f (Get-Date))
    $snap | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Log "Saved the Exchange Online connector settings to $path." OK
    $q = { param([string]$s) "'" + ($s -replace "'", "''") + "'" }
    foreach ($r in $todo) {
        $noun = "$($r.Type)Connector"
        Write-Log "Rollback: Set-$noun -Identity $(& $q $r.Connector) -$($r.Setting) $(& $q $r.Current)   (Exchange Online)"
        try {
            Invoke-Step "Set-$noun -Identity $(& $q $r.Connector) -$($r.Setting) $(& $q $r.New)   (Exchange Online)" {
                Invoke-Exo Set $noun @{ Identity = $r.Connector; $r.Setting = $r.New }
                $now = "$((Invoke-Exo Get $noun @{ Identity = $r.Connector }).($r.Setting))"
                if ($now -eq $r.New) { Write-Log "Exchange Online: $($r.Type) '$($r.Connector)' now has $($r.Setting) = $now." OK }
                else { Write-Log "Exchange Online: $($r.Type) '$($r.Connector)' shows $($r.Setting) = $now, expected $($r.New)." ERROR }
            }
        }
        catch { Write-Log "Exchange Online: $($r.Type) '$($r.Connector)' FAILED: $($_.Exception.Message)" ERROR }
    }
    if (-not (Test-DryRun)) { Write-Log 'Exchange Online connectors updated. Send a test message in both directions (cloud mailbox <-> on-premises mailbox) and check the message trace.' OK }
}

# ---------------------------------------------------------------------------------------------
# Rolling restart - tab 4
# ---------------------------------------------------------------------------------------------
function Invoke-RollingRestart {
    Assert-Exchange
    $servers = @(Get-SelectedServers)
    if (-not $servers) { throw 'Select at least one server on tab 1.' }
    # iisreset on the server that hosts this tool's Exchange session drops the session for a moment: do it last.
    $servers = @($servers | Where-Object { $_ -ne $env:COMPUTERNAME }) + @($servers | Where-Object { $_ -eq $env:COMPUTERNAME })
    $msg = "Restart IIS (iisreset /noforce) and the Microsoft Exchange Frontend Transport service, one server at a time:`n  $($servers -join "`n  ")`n`n" +
    'After each server the tool waits until HTTPS (443) answers again before the next one, and stops if a server does not come back. Clients on that server are disconnected for a moment.'
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Rolling restart')) { Write-Log 'Cancelled.' WARN; return }
    foreach ($s in $servers) {
        $fqdn = Get-ServerFqdn $s
        Invoke-Step "Invoke-Command -ComputerName $fqdn { iisreset /noforce }" {
            Invoke-Command -ComputerName $fqdn -ErrorAction Stop -ScriptBlock { $o = & iisreset.exe /noforce 2>&1 | Out-String; if ($LASTEXITCODE) { throw "iisreset exit code ${LASTEXITCODE}: $o" } }
        }
        Invoke-Step "Restart-Service MSExchangeFrontEndTransport on $fqdn" {
            Get-Service -ComputerName $fqdn -Name MSExchangeFrontEndTransport -ErrorAction Stop | Restart-Service -Force -ErrorAction Stop
        }
        if (Test-DryRun) { continue }
        $deadline = (Get-Date).AddMinutes(3); $served = $null
        while (-not $served) {
            try { $served = Get-RemoteTlsCertificate -HostName $fqdn -Port 443 -TimeoutMs 5000 } catch { }
            if ($served) { break }
            if ((Get-Date) -gt $deadline) { throw "$s does not answer on port 443 three minutes after the restart - stopped; the remaining servers were not restarted." }
            Wait-Ui 5
        }
        $isNew = $script:State.NewThumb -and $served.Thumbprint -eq $script:State.NewThumb
        Write-Log ('{0}: back online, port 443 serves {1}{2}.' -f $s, $served.Thumbprint, $(if ($isNew) { ' (the new certificate)' } elseif ($script:State.NewThumb) { ' - NOT the new certificate' } else { '' })) $(if ($script:State.NewThumb -and -not $isNew) { 'WARN' } else { 'OK' })
    }
    Write-Log 'Rolling restart finished. Run the verification again.' OK
}

# ---------------------------------------------------------------------------------------------
# Rollback snapshots - tab 3 (saved before Step B and Step C)
# ---------------------------------------------------------------------------------------------
function Save-ChangeSnapshot {
    param([string]$Before)
    $servers = @(Get-SelectedServers)
    Update-Inventory
    # $null = could not be read (never restored); '' = was empty (restored as empty, snapshot version 2+)
    $x509Name = { param($cmd, $s) try { "$((& $cmd -Server $s -ErrorAction Stop).X509CertificateName)" } catch { $null } }
    $srv = [ordered]@{}
    foreach ($s in $servers) {
        $srv[$s] = [ordered]@{
            # Every certificate bound to IIS, CA-issued first - a self-signed one too, so a server that had no
            # public certificate yet can be rolled back to its self-signed certificate.
            Iis               = @($script:State.Inventory | Where-Object { $_.Server -eq $s -and ($_.Services -split ',') -contains 'IIS' } |
                    Sort-Object @{ e = { $_.SelfSigned -eq 'True' } } | ForEach-Object { $_.Thumbprint })
            InternalTransport = "$($script:State.Servers[$s].InternalTransportThumb)"
            Pop               = & $x509Name 'Get-PopSettings' $s
            Imap              = & $x509Name 'Get-ImapSettings' $s
        }
    }
    $conns = New-Object System.Collections.Generic.List[object]
    try { foreach ($c in @(Get-SendConnector)) { $conns.Add([ordered]@{ Type = 'Send'; Identity = "$($c.Identity)"; Tls = "$($c.TlsCertificateName)" }) } }
    catch { Write-Log "Get-SendConnector failed: $($_.Exception.Message)" WARN }
    foreach ($s in $servers) {
        try { foreach ($c in @(Get-ReceiveConnector -Server $s)) { $conns.Add([ordered]@{ Type = 'Receive'; Identity = "$($c.Identity)"; Tls = "$($c.TlsCertificateName)" }) } }
        catch { Write-Log "${s}: Get-ReceiveConnector failed: $($_.Exception.Message)" WARN }
    }
    $hc = Get-HybridConfigSafe
    $snap = [ordered]@{
        Version = 2; Created = (Get-Date).ToString('s'); Before = $Before; NewThumbprint = $script:State.NewThumb
        Servers = $srv; Connectors = $conns.ToArray(); Hybrid = $(if ($hc) { "$($hc.TlsCertificateName)" } else { $null })
    }
    $path = Join-Path (Split-Path $script:LogFile) ('Snapshot_{0:yyyyMMdd_HHmmss}_before-{1}.json' -f (Get-Date), $Before)
    $snap | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Log "Saved the current configuration to $path (tab 3, ""Roll back from snapshot"", restores it)." OK
}

# What has to change to get back to the snapshot. One row per command; Kind selects the cmdlet.
function Get-RollbackPlan {
    param([Parameter(Mandatory)]$Snapshot)
    $plan = New-Object System.Collections.Generic.List[object]
    $q = { param([string]$s) if ($s) { "'" + ($s -replace "'", "''") + "'" } else { '$null' } }
    $add = { param($Kind, $Server, $Identity, $Value, $Text) $plan.Add([pscustomobject]@{ Kind = $Kind; Server = $Server; Identity = $Identity; Value = $Value; Text = $Text }) }
    $version = 0; [void][int]::TryParse("$($Snapshot.Version)", [ref]$version)
    foreach ($p in @($Snapshot.Servers.PSObject.Properties)) {
        $s = $p.Name; $v = $p.Value
        $want = @(@($v.Iis) | Where-Object { $_ })[0]
        if ($want) {
            $certs = @(Get-ExchangeCertificate -Server $s)
            $cur = @($certs | Where-Object { (Get-ServiceList $_) -contains 'IIS' } | ForEach-Object { "$($_.Thumbprint)" })
            if ($cur -notcontains $want) {
                if ($certs | Where-Object { "$($_.Thumbprint)" -eq $want }) { & $add 'IIS' $s $null $want "Enable-ExchangeCertificate -Server $s -Thumbprint $want -Services IIS -Force" }
                else { Write-Log "${s}: the snapshot's IIS certificate $want is no longer installed (removed on tab 5?) - IIS cannot be rolled back on this server." ERROR }
            }
        }
        if ("$($v.InternalTransport)") {
            $cur = "$((Get-TransportService -Identity $s).InternalTransportCertificateThumbprint)"
            if ($cur -ne "$($v.InternalTransport)") { & $add 'Transport' $s $null "$($v.InternalTransport)" "Set-TransportService -Identity $s -InternalTransportCertificateThumbprint $($v.InternalTransport)" }
        }
        foreach ($kind in 'Pop', 'Imap') {
            $raw = $v.$kind
            if ($null -eq $raw) { continue }                    # not readable when the snapshot was taken
            $want = "$raw"
            if (-not $want -and $version -lt 2) { continue }    # version 1 stored '' for "empty" and "not readable"
            try { $cur = "$((& "Get-${kind}Settings" -Server $s -ErrorAction Stop).X509CertificateName)" }
            catch { Write-Log "${s}: Get-${kind}Settings failed: $($_.Exception.Message) - $kind not rolled back." WARN; continue }
            if ($cur -ne $want) {
                & $add $kind $s $null $(if ($want) { $want } else { $null }) "Set-${kind}Settings -Server $s -X509CertificateName $(& $q $want)"
            }
        }
    }
    foreach ($c in @($Snapshot.Connectors)) {
        $get = if ($c.Type -eq 'Send') { 'Get-SendConnector' } else { 'Get-ReceiveConnector' }
        try { $cur = "$((& $get -Identity $c.Identity -ErrorAction Stop).TlsCertificateName)" }
        catch { Write-Log "Connector '$($c.Identity)' not found - skipped." WARN; continue }
        if ($cur -ne "$($c.Tls)") {
            $val = if ("$($c.Tls)") { "$($c.Tls)" } else { $null }
            & $add $c.Type $null $c.Identity $val "Set-$($c.Type)Connector -Identity $(& $q $c.Identity) -TlsCertificateName $(& $q $val)"
        }
    }
    if (@($Snapshot.CloudConnectors).Count) {
        if (-not (Test-ExoConnected)) { Write-Log 'The snapshot contains Exchange Online connectors: click "Check Exchange Online connectors" on tab 3 to sign in, then roll back again to restore them.' WARN }
        else {
            foreach ($c in @($Snapshot.CloudConnectors)) {
                # Exchange Online rows: Server holds the setting name (TlsSenderCertificateName / TlsDomain)
                try { $cur = "$((Invoke-Exo Get "$($c.Type)Connector" @{ Identity = "$($c.Identity)" }).($c.Setting))" }
                catch { Write-Log "Exchange Online connector '$($c.Identity)' not found - skipped." WARN; continue }
                if ($cur -ne "$($c.Value)") { & $add "Exo$($c.Type)" $c.Setting $c.Identity "$($c.Value)" "Set-$($c.Type)Connector -Identity $(& $q $c.Identity) -$($c.Setting) $(& $q "$($c.Value)")   (Exchange Online)" }
            }
        }
    }
    if ($null -ne $Snapshot.Hybrid) {
        $hc = Get-HybridConfigSafe
        if ($hc -and "$($hc.TlsCertificateName)" -ne "$($Snapshot.Hybrid)") {
            $val = if ("$($Snapshot.Hybrid)") { "$($Snapshot.Hybrid)" } else { $null }
            & $add 'Hybrid' $null $null $val "Set-HybridConfiguration -TlsCertificateName $(& $q $val)"
        }
    }
    $plan.ToArray()
}

function Invoke-Rollback {
    param([string]$Path)
    Assert-Exchange
    if (-not $Path) {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.InitialDirectory = Split-Path $script:LogFile
        $dlg.Filter = 'Snapshot (Snapshot_*.json)|Snapshot_*.json|All files (*.*)|*.*'
        if (-not $dlg.ShowDialog($script:Window)) { return }
        $Path = $dlg.FileName
    }
    $snap = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    Write-Log "Rollback: comparing the current configuration with $Path (saved $($snap.Created), before $($snap.Before))."
    $plan = @(Get-RollbackPlan -Snapshot $snap)
    if (-not $plan) { Write-Log 'Nothing to roll back - the configuration matches the snapshot.' OK; return }
    $msg = "Restore this configuration from the snapshot?`n`n$(($plan | ForEach-Object { '  ' + $_.Text }) -join "`n")`n`nThe new certificate stays installed (and enabled for SMTP); only the settings above change."
    if (Test-DryRun) { $msg += "`n`n(DRY RUN - nothing will be changed)" }
    if (-not (Confirm-Action $msg 'Roll back')) { Write-Log 'Rollback cancelled.' WARN; return }
    foreach ($r in $plan) {
        try {
            Invoke-Step $r.Text {
                switch ($r.Kind) {
                    'IIS' { Enable-ExchangeCertificate -Server $r.Server -Thumbprint $r.Value -Services IIS -Force -ErrorAction Stop }
                    'Transport' { Set-TransportService -Identity $r.Server -InternalTransportCertificateThumbprint $r.Value -ErrorAction Stop }
                    'Pop' { Set-PopSettings -Server $r.Server -X509CertificateName $r.Value -ErrorAction Stop }
                    'Imap' { Set-ImapSettings -Server $r.Server -X509CertificateName $r.Value -ErrorAction Stop }
                    'Send' { Set-SendConnector -Identity $r.Identity -TlsCertificateName $r.Value -ErrorAction Stop }
                    'Receive' { Set-ReceiveConnector -Identity $r.Identity -TlsCertificateName $r.Value -ErrorAction Stop }
                    'Hybrid' { Set-HybridConfiguration -TlsCertificateName $r.Value -ErrorAction Stop }
                    'ExoInbound' { Invoke-Exo Set InboundConnector @{ Identity = $r.Identity; $r.Server = $r.Value } }
                    'ExoOutbound' { Invoke-Exo Set OutboundConnector @{ Identity = $r.Identity; $r.Server = $r.Value } }
                }
                Write-Log "Restored: $($r.Text)" OK
            }
        }
        catch { Write-Log "Rollback step failed: $($r.Text): $($_.Exception.Message)" ERROR }
    }
    if (-not (Test-DryRun)) { Update-Inventory; Write-Log 'Rollback done. Wait a few minutes for transport, restart services if needed (tab 4, Rolling restart), then verify.' OK }
}

# ---------------------------------------------------------------------------------------------
# Edge Transport package - tab 3 (Edge servers are not in AD, so the tool cannot reach them)
# ---------------------------------------------------------------------------------------------
$script:EdgeScriptTemplate = @'
<#
    Generated by ExchangeCertTool on __DATE__ for certificate __THUMB__
    (__SUBJECT__).

    Run on each Edge Transport server in an elevated Exchange Management Shell:
        .\Install-EdgeCertificate.ps1 -WhatIf                   # show what would happen
        .\Install-EdgeCertificate.ps1                           # import and enable for SMTP
        .\Install-EdgeCertificate.ps1 -UpdatePinnedConnectors   # also switch receive connectors that pin another certificate

    The internal transport (default SMTP) certificate is kept, so the Edge Subscription stays valid.
    Delete this folder when you are done: certificate.pfx contains the private key.
#>
param([switch]$WhatIf, [switch]$UpdatePinnedConnectors)
$ErrorActionPreference = 'Stop'
$thumb = '__THUMB__'
$tls = '__TLSNAME__'
$pfx = Join-Path $PSScriptRoot 'certificate.pfx'
$server = $env:COMPUTERNAME
function Invoke-EdgeStep([string]$Text, [scriptblock]$Action) {
    if ($WhatIf) { Write-Host "[WhatIf] $Text" -ForegroundColor Cyan } else { Write-Host $Text -ForegroundColor Cyan; & $Action }
}

$before = "$((Get-TransportService -Identity $server).InternalTransportCertificateThumbprint)"
Write-Host "Internal transport certificate (used by the Edge Subscription): $before"
if (Get-ExchangeCertificate -Thumbprint $thumb -ErrorAction SilentlyContinue) { Write-Host "Certificate $thumb is already imported." -ForegroundColor Green }
else {
    $pw = Read-Host 'PFX password' -AsSecureString
    Invoke-EdgeStep 'Import-ExchangeCertificate -FileData <certificate.pfx> -Password <hidden>' { Import-ExchangeCertificate -FileData ([IO.File]::ReadAllBytes($pfx)) -Password $pw | Out-Null }
}
Invoke-EdgeStep "Enable-ExchangeCertificate -Thumbprint $thumb -Services SMTP -Force" { Enable-ExchangeCertificate -Thumbprint $thumb -Services SMTP -Force }
if (-not $WhatIf) {
    $after = "$((Get-TransportService -Identity $server).InternalTransportCertificateThumbprint)"
    if ($before -and $after -ne $before) {
        Invoke-EdgeStep "Set-TransportService -Identity $server -InternalTransportCertificateThumbprint $before   # restore" {
            Set-TransportService -Identity $server -InternalTransportCertificateThumbprint $before
        }
    }
}
foreach ($c in @(Get-ReceiveConnector -Server $server)) {
    $cur = "$($c.TlsCertificateName)"
    if (-not $cur -or $cur -eq $tls) { continue }
    if ($UpdatePinnedConnectors) {
        Write-Host "Rollback: Set-ReceiveConnector -Identity '$($c.Identity)' -TlsCertificateName '$cur'"
        Invoke-EdgeStep "Set-ReceiveConnector -Identity '$($c.Identity)' -TlsCertificateName '$tls'" { Set-ReceiveConnector -Identity $c.Identity -TlsCertificateName $tls }
    }
    else { Write-Host "Connector '$($c.Identity)' pins $cur - run again with -UpdatePinnedConnectors to switch it to the new certificate." -ForegroundColor Yellow }
}
Write-Host 'Done. If port 25 still offers the old certificate, restart MSExchangeTransport in a quiet period. Then delete this folder.' -ForegroundColor Green
'@

function New-EdgePackage {
    Assert-Validated
    if (-not $script:State.PfxPath) { throw 'The Edge package needs the PFX file: Edge servers are not in Active Directory, so the certificate cannot be copied from Exchange. Load the PFX on tab 2.' }
    $dir = Join-Path (Split-Path $script:LogFile) ('EdgePackage_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
    $msg = "Create a folder with a copy of the PFX and an install script for Edge Transport servers?`n`n  $dir`n`n" +
    'The PFX password is not stored - the script asks for it. Copy the folder to each Edge server, run Install-EdgeCertificate.ps1 in the Exchange Management Shell, then delete the folder.'
    if (-not (Confirm-Action $msg 'Edge Transport package')) { Write-Log 'Cancelled.' WARN; return }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item -LiteralPath $script:State.PfxPath -Destination (Join-Path $dir 'certificate.pfx')
    $new = $script:State.NewCert
    $tls = "<I>$($new.Issuer)<S>$($new.Subject)"
    $text = $script:EdgeScriptTemplate.Replace('__DATE__', (Get-Date).ToString('yyyy-MM-dd HH:mm')).Replace('__THUMB__', $script:State.NewThumb)
    $text = $text.Replace('__SUBJECT__', ($new.Subject -replace '#>', '')).Replace('__TLSNAME__', ($tls -replace "'", "''"))
    [IO.File]::WriteAllText((Join-Path $dir 'Install-EdgeCertificate.ps1'), $text, (New-Object System.Text.UTF8Encoding($true)))
    Write-Log "Edge Transport package created: $dir (certificate.pfx + Install-EdgeCertificate.ps1). It contains the private key - delete it after use." OK
}

# ---------------------------------------------------------------------------------------------
# HAProxy package - tab 3 (a load balancer that terminates TLS needs the same certificate as Exchange)
# ---------------------------------------------------------------------------------------------
# The PFX is converted to HAProxy's PEM format ON the HAProxy host with openssl, so the private key is never
# written unencrypted on Windows. Written with LF line endings (this .ps1 is stored with CRLF).
$script:HaproxyScriptTemplate = @'
#!/usr/bin/env bash
# Generated by ExchangeCertTool on __DATE__ for certificate __THUMB__
# (__SUBJECT__).
#
# Installs the certificate on an HAProxy host that terminates TLS for Exchange. Run as root in this folder:
#   bash install-haproxy-cert.sh --check                  # convert and verify only, change nothing
#   bash install-haproxy-cert.sh                          # install to __TARGET__
#   bash install-haproxy-cert.sh /etc/haproxy/certs/x.pem # install to another file
# Environment: HAPROXY_CFG (default /etc/haproxy/haproxy.cfg), BACKUP_DIR (default /root/haproxy-cert-backups),
#              PFXPASS (PFX password; asked for when not set).
# The previous file is backed up OUTSIDE the certificate folder (HAProxy loads every file in a 'crt' folder).
# Delete this folder afterwards: certificate.pfx contains the private key.
set -euo pipefail
THUMB='__THUMB__'
NAME='__NAME__'
CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then CHECK_ONLY=1; shift; fi
TARGET="${1:-__TARGET__}"
CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
BACKUP_DIR="${BACKUP_DIR:-/root/haproxy-cert-backups}"
DIR="$(cd "$(dirname "$0")" && pwd)"
PFX="$DIR/certificate.pfx"
fail() { echo "ERROR: $*" >&2; exit 1; }
command -v openssl >/dev/null || fail "openssl is not installed."
[ -f "$PFX" ] || fail "certificate.pfx not found next to this script."
umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if [ -z "${PFXPASS:-}" ]; then read -rsp "PFX password: " PFXPASS; echo; fi
export PFXPASS
# OpenSSL 3 needs -legacy for PFX files with older encryption (common for Windows/Posh-ACME exports).
p12() { openssl pkcs12 -in "$PFX" -passin env:PFXPASS "$@" 2>/dev/null || openssl pkcs12 -legacy -in "$PFX" -passin env:PFXPASS "$@"; }
p12 -clcerts -nokeys -out "$WORK/leaf.raw" || fail "cannot read certificate.pfx (wrong password?)"
p12 -cacerts -nokeys -out "$WORK/chain.raw" || true
p12 -nocerts -nodes -out "$WORK/key.raw" || fail "cannot read the private key from certificate.pfx"
unset PFXPASS
pem_certs() { sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$1"; }
pem_certs "$WORK/leaf.raw" > "$WORK/leaf.pem"
FP="$(openssl x509 -in "$WORK/leaf.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':' | tr 'a-f' 'A-F')"
[ "$FP" = "$THUMB" ] || fail "certificate.pfx contains $FP, expected $THUMB."
openssl pkey -in "$WORK/key.raw" -out "$WORK/key.pem" 2>/dev/null || fail "the private key in certificate.pfx cannot be read."
[ "$(openssl x509 -in "$WORK/leaf.pem" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$WORK/key.pem" -pubout | openssl sha256)" ] ||
    fail "the private key does not belong to the certificate."
{ cat "$WORK/leaf.pem"; [ -s "$WORK/chain.raw" ] && pem_certs "$WORK/chain.raw"; cat "$WORK/key.pem"; } > "$WORK/haproxy.pem"
echo "Certificate: $(openssl x509 -in "$WORK/leaf.pem" -noout -subject), $(openssl x509 -in "$WORK/leaf.pem" -noout -enddate)"
echo "Chain certificates: $(grep -c 'BEGIN CERTIFICATE' "$WORK/haproxy.pem") (including the certificate)"
if [ "$CHECK_ONLY" = 1 ]; then echo "Check OK - nothing was changed."; exit 0; fi
[ -f "$CFG" ] || fail "$CFG not found (set HAPROXY_CFG)."
command -v haproxy >/dev/null || fail "haproxy is not on PATH - run this on the HAProxy host. Nothing was changed."
if ! grep -qF "$TARGET" "$CFG" && ! grep -qF "$(dirname "$TARGET")" "$CFG"; then
    echo "WARNING: $CFG does not mention $TARGET or its folder. If HAProxy only passes TLS through (mode tcp), it needs no certificate."
fi
mkdir -p "$(dirname "$TARGET")" "$BACKUP_DIR"
BACKUP=""
if [ -f "$TARGET" ]; then BACKUP="$BACKUP_DIR/$(basename "$TARGET").$(date +%Y%m%d%H%M%S)"; cp -p "$TARGET" "$BACKUP"; echo "Backup: $BACKUP"; fi
cp "$WORK/haproxy.pem" "$TARGET.new"
chmod 600 "$TARGET.new"
mv -f "$TARGET.new" "$TARGET"
if ! haproxy -c -f "$CFG"; then
    echo "HAProxy configuration check FAILED - restoring the previous certificate." >&2
    if [ -n "$BACKUP" ]; then cp -p "$BACKUP" "$TARGET"; else rm -f "$TARGET"; fi
    exit 1
fi
if command -v systemctl >/dev/null; then systemctl reload haproxy; else service haproxy reload; fi
echo "Installed $TARGET and reloaded HAProxy."
echo "Check: echo | openssl s_client -connect 127.0.0.1:443 -servername $NAME 2>/dev/null | openssl x509 -noout -fingerprint -sha1"
echo "Then run tab 4 of ExchangeCertTool with this HAProxy as an extra endpoint, and delete this folder."
'@

function New-HaproxyPackage {
    Assert-Validated
    if (-not $script:State.PfxPath) { throw 'The HAProxy package needs the PFX file (HAProxy is not an Exchange server, so the certificate cannot be copied from Exchange). Load the PFX on tab 2, e.g. with "Load last Let''s Encrypt/ACME certificate".' }
    $names = @($script:State.NewNames)
    $name = @($names | Where-Object { $_ -notmatch '\*' } | Select-Object -First 1)[0]
    if (-not $name) { $name = (@($names)[0]) -replace '^\*\.', 'mail.' }
    $target = '/etc/haproxy/certs/{0}.pem' -f (($names | Select-Object -First 1) -replace '^\*\.', 'wildcard.')
    $dir = Join-Path (Split-Path $script:LogFile) ('HaproxyPackage_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
    $msg = "Create a folder with a copy of the PFX and an install script for HAProxy?`n`n  $dir`n`n" +
    "Copy it to the HAProxy host and run: bash install-haproxy-cert.sh --check, then bash install-haproxy-cert.sh (default target $target).`n`n" +
    'The script converts the PFX with openssl on the HAProxy host, checks the thumbprint and the key, backs up the old file outside the certificate folder, runs haproxy -c and reloads (restores the old file if the check fails). The PFX password is not stored. Only needed if HAProxy terminates TLS (mode http / ssl crt); TCP passthrough needs nothing.'
    if (-not (Confirm-Action $msg 'HAProxy package')) { Write-Log 'Cancelled.' WARN; return }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item -LiteralPath $script:State.PfxPath -Destination (Join-Path $dir 'certificate.pfx')
    $subject = ("$($script:State.NewCert.Subject)" -replace '[
\n]', ' ')
    $text = $script:HaproxyScriptTemplate.Replace('__DATE__', (Get-Date).ToString('yyyy-MM-dd HH:mm')).Replace('__THUMB__', "$($script:State.NewThumb)".ToUpperInvariant())
    $text = $text.Replace('__SUBJECT__', $subject).Replace('__NAME__', ($name -replace "'", '')).Replace('__TARGET__', $target)
    $text = $text -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $dir 'install-haproxy-cert.sh'), $text, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log "HAProxy package created: $dir (certificate.pfx + install-haproxy-cert.sh). Copy it, e.g.: scp -r `"$dir`" root@<haproxy>:/root/  - then run bash install-haproxy-cert.sh --check on the HAProxy host. It contains the private key - delete it after use." OK
}

# ---------------------------------------------------------------------------------------------
# Free ACME certificates (Let's Encrypt, ZeroSSL, Google, SSL.com, Actalis) via Posh-ACME - tab "1b\"
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
function Get-ModuleSearchRoots {
    $docs = @([Environment]::GetFolderPath('MyDocuments'), (Join-Path $env:USERPROFILE 'Documents'))
    if ($env:OneDrive) { $docs += (Join-Path $env:OneDrive 'Documents') }
    $roots = @(Join-Path $PSScriptRoot 'Modules')   # portable copy: Save-Module <name> -Path .\Modules
    foreach ($d in ($docs | Where-Object { $_ } | Select-Object -Unique)) {
        $roots += (Join-Path $d 'WindowsPowerShell\Modules')
        $roots += (Join-Path $d 'PowerShell\Modules')
    }
    $roots += (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
    $roots += (Join-Path $env:ProgramFiles 'PowerShell\Modules')
    $roots += @($env:PSModulePath -split ';' | Where-Object { $_ })
    @($roots | Where-Object { $_ } | Select-Object -Unique)
}

# Path of the newest <Name>.psd1 in the module folders of Windows PowerShell, PowerShell 7, OneDrive and .\Modules, or $null.
# Windows PowerShell 5.1 does not search the PowerShell 7 folders itself, so modules installed from pwsh are found here too.
function Find-ModuleManifest {
    param([Parameter(Mandatory)][string]$Name)
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($root in Get-ModuleSearchRoots) {
        $dir = Join-Path $root $Name
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        foreach ($psd in @(Get-ChildItem -LiteralPath $dir -Filter "$Name.psd1" -Recurse -Depth 1 -File -ErrorAction SilentlyContinue)) {
            $ver = [version]'0.0'
            try { $ver = [version](Import-PowerShellDataFile -LiteralPath $psd.FullName).ModuleVersion } catch { }
            $found.Add([pscustomobject]@{ Path = $psd.FullName; Version = $ver })
        }
    }
    $best = $found | Sort-Object Version -Descending | Select-Object -First 1
    if ($best) { return $best.Path }
    return $null
}

function Find-PoshAcmeManifest { Find-ModuleManifest 'Posh-ACME' }

function Test-PoshAcme { [bool](Get-Command New-PAOrder -ErrorAction SilentlyContinue) -or [bool](Find-PoshAcmeManifest) }

function Write-PoshAcmeDiagnostics {
    Write-Log "Posh-ACME not found for $env:USERDOMAIN\$env:USERNAME (PowerShell $($PSVersionTable.PSVersion), $([IntPtr]::Size * 8)-bit). Searched:" WARN
    foreach ($r in Get-ModuleSearchRoots) { Write-Log ("    {0}  {1}" -f $(if (Test-Path -LiteralPath $r) { '[exists] ' } else { '[missing]' }), $r) }
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

# ---------------------------------------------------------------------------------------------
# Cloudflare DNS (DNS-01 automatic) - uses the Posh-ACME "Cloudflare" plugin with a scoped API token
# ---------------------------------------------------------------------------------------------
$script:CfApi = 'https://api.cloudflare.com/client/v4'
$script:CfTokenFile = Join-Path $env:LOCALAPPDATA 'ExchangeCertTool\cloudflare-token.dpapi'

function Get-CfToken {
    $t = $script:ui.LeCfTokenBox.Password.Trim()
    if (-not $t) { throw 'Enter the Cloudflare API token.' }
    if ($t -match '\s') { throw 'The Cloudflare API token must not contain spaces.' }
    $t
}

function Invoke-CfApi {
    param([Parameter(Mandatory)][string]$Path, [string]$Method = 'GET', [hashtable]$Query, $Body, [Parameter(Mandatory)][string]$Token)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $uri = $script:CfApi + $Path
    if ($Query) { $uri += '?' + (($Query.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, [uri]::EscapeDataString("$($_.Value)") }) -join '&') }
    $p = @{ Uri = $uri; Method = $Method; Headers = @{ Authorization = "Bearer $Token" }; ContentType = 'application/json'; UseBasicParsing = $true; TimeoutSec = 30; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Compress -Depth 5) }
    try { Invoke-RestMethod @p }
    catch {
        $detail = $_.Exception.Message
        try {
            $resp = $_.Exception.Response
            if ($resp) {
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $raw = $sr.ReadToEnd(); $sr.Close()
                $j = $raw | ConvertFrom-Json
                if ($j.errors) { $detail = (@($j.errors | ForEach-Object { "$($_.code): $($_.message)" }) -join '; ') }
            }
        }
        catch { }
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { $j = $_.ErrorDetails.Message | ConvertFrom-Json; if ($j.errors) { $detail = (@($j.errors | ForEach-Object { "$($_.code): $($_.message)" }) -join '; ') } } catch { }
        }
        throw "Cloudflare API $Method $Path failed: $detail"
    }
}

# Finds the deepest Cloudflare zone that contains $Name (same logic as the Posh-ACME plugin).
function Find-CfZone {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Token)
    $pieces = ($Name -replace '^\*\.', '').Split('.')
    for ($i = 0; $i -lt ($pieces.Count - 1); $i++) {
        $candidate = $pieces[$i..($pieces.Count - 1)] -join '.'
        $r = Invoke-CfApi -Path '/zones' -Query @{ name = $candidate } -Token $Token
        if ($r.result -and @($r.result).Count -gt 0) { return @($r.result)[0] }
    }
    return $null
}

function Test-CloudflareSetup {
    param([switch]$Quiet)
    $token = Get-CfToken
    $names = @(Get-LeNames)
    $rows = New-Object System.Collections.Generic.List[object]
    $ok = $true

    try {
        $v = Invoke-CfApi -Path '/user/tokens/verify' -Token $token
        $rows.Add([pscustomobject]@{ Name = '(API token)'; Type = 'verify'; Record = "status: $($v.result.status)"; Value = ''; Status = $(if ("$($v.result.status)" -eq 'active') { 'PASS' } else { 'FAIL - token is not active' }) })
        if ("$($v.result.status)" -ne 'active') { $ok = $false }
    }
    catch {
        # Account-owned tokens cannot use /user/tokens/verify; the zone lookups below still prove they work.
        $rows.Add([pscustomobject]@{ Name = '(API token)'; Type = 'verify'; Record = ''; Value = ''; Status = "INFO - $($_.Exception.Message) (normal for account-owned tokens; zone checks below decide)" })
    }

    $zones = @{}
    foreach ($n in $names) {
        try {
            $z = Find-CfZone -Name $n -Token $token
            if (-not $z) {
                $rows.Add([pscustomobject]@{ Name = $n; Type = 'zone'; Record = ''; Value = ''; Status = 'FAIL - no Cloudflare zone found. The token needs Zone:Read for this zone, or the domain is not on Cloudflare DNS.' })
                $ok = $false; continue
            }
            $zones["$($z.id)"] = $z
            $rows.Add([pscustomobject]@{ Name = $n; Type = 'zone'; Record = "_acme-challenge.$($n -replace '^\*\.', '')"; Value = "zone $($z.name)"; Status = $(if ("$($z.status)" -eq 'active') { 'PASS' } else { "WARN - zone status is '$($z.status)'" }) })
        }
        catch { $rows.Add([pscustomobject]@{ Name = $n; Type = 'zone'; Record = ''; Value = ''; Status = "FAIL - $($_.Exception.Message)" }); $ok = $false }
    }

    foreach ($z in $zones.Values) {
        try {
            [void](Invoke-CfApi -Path "/zones/$($z.id)/dns_records" -Query @{ type = 'TXT'; per_page = 5 } -Token $token)
            $rows.Add([pscustomobject]@{ Name = $z.name; Type = 'DNS read'; Record = ''; Value = ''; Status = 'PASS' })
        }
        catch { $rows.Add([pscustomobject]@{ Name = $z.name; Type = 'DNS read'; Record = ''; Value = ''; Status = "FAIL - $($_.Exception.Message)" }); $ok = $false; continue }

        $testName = "_certtool-test-$([guid]::NewGuid().ToString('N').Substring(0, 8)).$($z.name)"
        if (Test-DryRun) {
            Write-Log "[DRY RUN] would create and delete TXT $testName in zone $($z.name) to prove DNS edit permission" CMD
            $rows.Add([pscustomobject]@{ Name = $z.name; Type = 'DNS edit'; Record = $testName; Value = ''; Status = 'SKIPPED - untick Dry run to test write access (creates and deletes one TXT record)' })
            continue
        }
        try {
            Write-Log "Cloudflare: create TXT $testName (write test)" CMD
            $created = Invoke-CfApi -Path "/zones/$($z.id)/dns_records" -Method POST -Body @{ type = 'TXT'; name = $testName; content = 'exchange-cert-tool write test'; ttl = 60 } -Token $token
            try {
                Write-Log "Cloudflare: delete TXT $testName" CMD
                [void](Invoke-CfApi -Path "/zones/$($z.id)/dns_records/$($created.result.id)" -Method DELETE -Token $token)
                $rows.Add([pscustomobject]@{ Name = $z.name; Type = 'DNS edit'; Record = $testName; Value = ''; Status = 'PASS (created and deleted a test TXT record)' })
            }
            catch {
                $rows.Add([pscustomobject]@{ Name = $z.name; Type = 'DNS edit'; Record = $testName; Value = ''; Status = "WARN - created but could not delete: $($_.Exception.Message). Delete it in the Cloudflare dashboard." })
            }
        }
        catch { $rows.Add([pscustomobject]@{ Name = $z.name; Type = 'DNS edit'; Record = $testName; Value = ''; Status = "FAIL - $($_.Exception.Message). The token needs Zone > DNS > Edit." }); $ok = $false }
    }

    foreach ($r in $rows) { Write-Log ("Cloudflare check {0} [{1}]: {2}" -f $r.Name, $r.Type, $r.Status) $(if ($r.Status -like 'FAIL*') { 'ERROR' } elseif ($r.Status -like 'PASS*') { 'OK' } else { 'INFO' }) }
    if (-not $Quiet) {
        $script:ui.LeGrid.ItemsSource = (ConvertTo-DataTable $rows.ToArray() @('Name', 'Type', 'Record', 'Value', 'Status')).DefaultView
        $script:ui.LeStatusText.Text = if ($ok) { 'Cloudflare token works for all names.' } else { 'Cloudflare check found problems - see the Status column.' }
    }
    if ($ok) { Save-CfToken }
    return $ok
}

function Save-CfToken {
    if (-not $script:ui.LeCfRememberCheck.IsChecked) {
        if (Test-Path -LiteralPath $script:CfTokenFile) { Remove-Item -LiteralPath $script:CfTokenFile -Force; Write-Log 'Removed the saved Cloudflare token.' }
        return
    }
    $dir = Split-Path $script:CfTokenFile
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # DPAPI (CurrentUser): only this Windows user on this machine can decrypt it.
    $script:ui.LeCfTokenBox.SecurePassword | ConvertFrom-SecureString | Set-Content -LiteralPath $script:CfTokenFile -Encoding ASCII
    Write-Log "Cloudflare token saved encrypted for $env:USERDOMAIN\$env:USERNAME ($script:CfTokenFile)."
}

function Restore-CfToken {
    if (-not (Test-Path -LiteralPath $script:CfTokenFile)) { return }
    try {
        $sec = Get-Content -LiteralPath $script:CfTokenFile -Raw | ForEach-Object { $_.Trim() } | ConvertTo-SecureString
        $script:ui.LeCfTokenBox.Password = (New-Object System.Net.NetworkCredential('', $sec)).Password
        $script:ui.LeCfRememberCheck.IsChecked = $true
        Write-Log 'Loaded the saved Cloudflare token.'
    }
    catch { Write-Log "Could not read the saved Cloudflare token (saved by another user?): $($_.Exception.Message)" WARN }
}

# Hint: are the names hosted on Cloudflare DNS? (public NS lookup, no token needed)
function Get-CfDnsHint {
    $names = @()
    try { $names = @(Get-LeNames) } catch { return }
    $onCf = @()
    foreach ($n in $names) {
        $pieces = ($n -replace '^\*\.', '').Split('.')
        for ($i = 0; $i -lt ($pieces.Count - 1); $i++) {
            $cand = $pieces[$i..($pieces.Count - 1)] -join '.'
            $ns = @(Resolve-PublicName -Name $cand -Type NS | Where-Object { $_.Type -eq 'NS' -and "$($_.Section)" -eq 'Answer' } | ForEach-Object { "$($_.NameHost)" })
            if ($ns) { if ($ns -match '\.ns\.cloudflare\.com$') { $onCf += $cand }; break }
        }
    }
    $onCf = @($onCf | Select-Object -Unique)
    if ($onCf) {
        Write-Log "Public DNS for $($onCf -join ', ') is hosted on Cloudflare - the ""DNS-01 automatic: Cloudflare"" option can create the TXT records for you." OK
        $script:ui.LeCfDetectedText.Text = "Detected: $($onCf -join ', ') uses Cloudflare DNS."
    }
}

function Get-LeMode {
    if ($script:ui.LeCfRadio.IsChecked) { return 'Cloudflare' }
    if ($script:ui.LeDnsManualRadio.IsChecked) { return 'DNSManual' }
    if ($script:ui.LeDnsPluginRadio.IsChecked) { return 'DNSPlugin' }
    return 'HTTP'
}

function Get-LeNames {
    param([switch]$AllowInternal)   # CSR for an internal CA
    $names = @($script:ui.LeNamesBox.Text -split '[\r\n,;\s]+' |
        ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $names) { throw 'Enter at least one name for the certificate.' }
    foreach ($n in $names) {
        if ($n -notmatch '^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$') { throw "Not a valid DNS name: $n" }
        if (-not $AllowInternal -and $n -match '\.(local|lan|internal|corp|intra|localdomain|home|private)$') { throw "Public CAs cannot issue certificates for internal names: $n" }
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
        if (-not (Set-LeNamesFromCurrentCert -Auto)) { Set-LeNamesFromExchange }
        Get-CfDnsHint
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
    if ($mode -eq 'Cloudflare') {
        $null = Get-CfToken
        if (-not (Test-DryRun)) {
            Write-Log 'Checking the Cloudflare token and zones before ordering...'
            if (-not (Test-CloudflareSetup -Quiet)) { throw 'The Cloudflare check failed - click "Test Cloudflare token" to see the details.' }
        }
        $mode = 'DNSPlugin'
        $plugin = 'Cloudflare'
        $pluginArgs = @{ CFToken = $script:ui.LeCfTokenBox.SecurePassword.Copy() }
    }
    elseif ($mode -eq 'DNSPlugin') {
        $plugin = $script:ui.LePluginCombo.Text.Trim()
        if (-not $plugin) { throw 'Choose a DNS plugin (e.g. Cloudflare, Route53, Azure).' }
        $pluginArgs = ConvertFrom-LePluginArgs $script:ui.LePluginArgsBox.Text
    }
    if ($mode -eq 'HTTP') { $roots = @(Get-LeWebroots) }

    $modeText = @{ HTTP = 'HTTP-01 (file in IIS)'; DNSManual = 'DNS-01 (you add TXT records)'; DNSPlugin = $(if ($plugin -eq 'Cloudflare') { 'DNS-01 automatic via Cloudflare API' } else { "DNS-01 via plugin $plugin" }) }[$mode]
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
    if ($plugin -eq 'Cloudflare') { Save-CfToken }
    $script:Le.Mode = $mode; $script:Le.Plugin = $plugin; $script:Le.PluginArgs = $pluginArgs; $script:Le.Names = $names
    $script:Le.UiMode = Get-LeMode   # 'Cloudflare' is kept apart from other plugins for the renewal settings
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
    if (-not $script:Le.Provider.Staging) {
        try { Save-RenewalProfile } catch { Write-Log "Could not save the renewal settings: $($_.Exception.Message)" WARN }
    }

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
# Unattended renewal (-Renew) for a scheduled task
# ---------------------------------------------------------------------------------------------
$script:RenewalProfileFile = Join-Path $env:LOCALAPPDATA 'ExchangeCertTool\renewal.json'

# Saved after every certificate issued by a production CA: what -Renew needs to request the next one.
# Secrets are not in it: the Cloudflare token has its own DPAPI file; plugin arguments are DPAPI-encrypted here.
function Save-RenewalProfile {
    $mode = $script:Le.UiMode
    if ($mode -eq 'DNSManual') { Write-Log 'Automatic renewal (-Renew) cannot use DNS-01 manual. Use HTTP-01, Cloudflare or a DNS plugin to make renewals automatic.' INFO; return }
    if ($mode -eq 'Cloudflare' -and -not $script:ui.LeCfRememberCheck.IsChecked) { Write-Log 'For automatic renewal (-Renew), tick "Remember the token" on tab 1b and test the token once.' WARN }
    $argsText = $script:ui.LePluginArgsBox.Text.Trim()
    $p = [ordered]@{
        Version    = 1
        Saved      = (Get-Date).ToString('s')
        User       = "$env:USERDOMAIN\$env:USERNAME"
        Provider   = $script:Le.Provider.Server
        Names      = @($script:Le.Names)
        Mode       = $mode
        Plugin     = "$($script:Le.Plugin)"
        PluginArgs = $(if ($mode -eq 'DNSPlugin' -and $argsText) { ConvertTo-SecureString $argsText -AsPlainText -Force | ConvertFrom-SecureString } else { '' })
        Webroot    = $script:ui.LeWebrootBox.Text.Trim()
        KeyLength  = "$($script:ui.LeKeyCombo.SelectedItem.Content)"
        Email      = $script:ui.LeEmailBox.Text.Trim()
        Servers    = @(Get-SelectedServers)
    }
    $dir = Split-Path $script:RenewalProfileFile
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $p | ConvertTo-Json | Set-Content -LiteralPath $script:RenewalProfileFile -Encoding UTF8
    Write-Log "Renewal settings saved for -Renew: $script:RenewalProfileFile ($($p.Provider), $mode, $($p.Names.Count) name(s), servers $($p.Servers -join ', '))."
}

function Get-RenewalProfile {
    if (-not (Test-Path -LiteralPath $script:RenewalProfileFile)) {
        throw "No renewal settings found ($script:RenewalProfileFile). Request a certificate once in the GUI as $env:USERDOMAIN\$env:USERNAME from a production CA with HTTP-01, Cloudflare or a DNS plugin - the settings are saved when it is issued."
    }
    Get-Content -LiteralPath $script:RenewalProfileFile -Raw | ConvertFrom-Json
}

# Puts the saved settings into the (hidden) window, so Start-LeRequest runs exactly as from the GUI.
function Set-RenewalUi {
    param([Parameter(Mandatory)]$Settings)
    $ui = $script:ui
    $idx = -1
    for ($k = 0; $k -lt $script:AcmeProviders.Count; $k++) { if ($script:AcmeProviders[$k].Server -eq "$($Settings.Provider)") { $idx = $k } }
    if ($idx -lt 0 -or $script:AcmeProviders[$idx].Staging) { throw "The saved certificate authority '$($Settings.Provider)' is not a production CA of this tool." }
    $ui.LeProviderCombo.SelectedIndex = $idx
    $ui.LeTosCheck.IsChecked = $true   # accepted when the account was created in the GUI
    $ui.LeEmailBox.Text = "$($Settings.Email)"
    $ui.LeNamesBox.Text = (@($Settings.Names) -join "`r`n")
    foreach ($it in $ui.LeKeyCombo.Items) { if ("$($it.Content)" -eq "$($Settings.KeyLength)") { $ui.LeKeyCombo.SelectedItem = $it } }
    switch ("$($Settings.Mode)") {
        'HTTP' { $ui.LeHttpRadio.IsChecked = $true; if ("$($Settings.Webroot)") { $ui.LeWebrootBox.Text = "$($Settings.Webroot)" } }
        'Cloudflare' {
            if (-not $ui.LeCfTokenBox.Password) { throw 'No saved Cloudflare token for this user. In the GUI, paste the token, tick "Remember the token" and click "Test Cloudflare token".' }
            $ui.LeCfRadio.IsChecked = $true
        }
        'DNSPlugin' {
            $ui.LeDnsPluginRadio.IsChecked = $true
            $ui.LePluginCombo.Text = "$($Settings.Plugin)"
            if ("$($Settings.PluginArgs)") { $ui.LePluginArgsBox.Text = (New-Object System.Net.NetworkCredential('', (ConvertTo-SecureString "$($Settings.PluginArgs)"))).Password }
        }
        default { throw "Challenge type '$($Settings.Mode)' cannot run unattended." }
    }
}

# Reasons not to touch Exchange with the validated certificate during an unattended run.
function Get-RenewalBlockers {
    param([object[]]$OldIis)
    $oldNames = @($OldIis | ForEach-Object { $_.Domains; if ("$($_.Subject)" -match '(?:^|,\s*)CN=([^,]+)') { $Matches[1].Trim() } } | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() })
    $lost = @($script:State.MissingHosts | Where-Object { $oldNames.Count -and (Test-HostCovered -HostName $_ -CertNames $oldNames) })
    if ($lost) { "the new certificate does not cover $($lost -join ', '), which the current certificate covers" }
    @($script:State.BlockingIssues)
}

function Send-RenewalReport {
    param([string]$Result)
    if (-not $NotifyTo) { return }
    $from = $NotifyFrom
    if (-not $from) {
        try { $d = "$((Get-AcceptedDomain | Where-Object { $_.Default } | Select-Object -First 1).DomainName)"; if ($d) { $from = "ExchangeCertTool@$d" } } catch { }
    }
    if (-not $from) { $from = "ExchangeCertTool@$env:USERDNSDOMAIN" }
    try {
        Send-MailMessage -SmtpServer $SmtpServer -From $from -To $NotifyTo -Subject "[ExchangeCertTool] Certificate renewal $Result on $env:COMPUTERNAME" `
            -Body (Get-Content -LiteralPath $script:LogFile -Raw) -Encoding UTF8 -ErrorAction Stop
        Write-Log "Report sent to $($NotifyTo -join ', ') via $SmtpServer." OK
    }
    catch { Write-Log "Could not send the report to $($NotifyTo -join ', ') via ${SmtpServer}: $($_.Exception.Message)" ERROR }
}

# Runs the GUI steps without the GUI. Sets $script:RenewExitCode: 0 = done or nothing to do, 1 = failed.
function Invoke-UnattendedRenewal {
    $script:Unattended = $true
    $script:RenewExitCode = 1
    $result = 'FAILED'
    try {
        Assert-Exchange
        $settings = Get-RenewalProfile
        New-MainWindow
        Register-UiEvents
        $ui = $script:ui
        $ui.DryRunCheck.IsChecked = -not $Live
        Write-Log ('Unattended renewal ({0}) for {1}; settings saved {2} by {3}.' -f $(if ($Live) { 'LIVE' } else { 'DRY RUN - add -Live to make changes' }), (@($settings.Names) -join ', '), $settings.Saved, $settings.User)

        Update-ServerList
        if (@($settings.Servers).Count) {
            $ui.ServerList.SelectedItems.Clear()
            foreach ($s in @($settings.Servers)) {
                if ($ui.ServerList.Items -contains $s) { [void]$ui.ServerList.SelectedItems.Add($s) } else { Write-Log "Server $s from the renewal settings is no longer a mailbox server - skipped." WARN }
            }
            foreach ($s in @($ui.ServerList.Items | Where-Object { $_ -notin @($settings.Servers) })) { Write-Log "Mailbox server $s is not in the renewal settings - it does not get the new certificate. Renew once in the GUI with all servers selected to include it." WARN }
        }
        if (-not @(Get-SelectedServers).Count) { throw 'None of the servers in the renewal settings exists.' }
        Update-Inventory
        $oldIis = @(Get-CurrentIisCertificates)
        if ($oldIis) {
            $days = [int][math]::Floor((($oldIis | ForEach-Object { [datetime]$_.NotAfter } | Measure-Object -Minimum).Minimum - (Get-Date)).TotalDays)
            Write-Log "Current IIS certificate(s): $(($oldIis | ForEach-Object { "$($_.Thumbprint) ($($_.Subject), exp $(([datetime]$_.NotAfter).ToString('yyyy-MM-dd')))" }) -join '; '). $days day(s) left."
            if (-not $ForceRenew -and $days -ge $RenewDays) {
                Write-Log "More than $RenewDays days left - nothing to do. (-ForceRenew renews anyway.)" OK
                $result = 'NOTNEEDED'; $script:RenewExitCode = 0; return
            }
        }
        else { Write-Log 'No CA-issued certificate is bound to IIS on the selected servers - requesting one.' WARN }

        # A certificate that an earlier run issued but did not finish installing (e.g. import failed) is reused, so
        # repeated failures do not use up the CA's rate limits (Let's Encrypt: 5 identical certificates per week).
        # Never the certificate that is already on IIS: with -ForceRenew it has more than -RenewDays left, and
        # "renewing" to it would change nothing. Without a known thumbprint, -ForceRenew does not reuse at all.
        $first = "$(@($settings.Names)[0])"
        $onIis = @($oldIis | ForEach-Object { "$($_.Thumbprint)" })
        Reset-Validation   # start from nothing: only a certificate validated in this run may be installed
        $reuse = @(Find-AcmeSavedCertificates | Where-Object {
                $_.MainDomain -eq $first -and $_.Server -notmatch 'stag|test|preprod' -and $_.Expires -and ($_.Expires - (Get-Date)).TotalDays -gt $RenewDays -and
                $(if ($_.Thumbprint) { $onIis -notcontains $_.Thumbprint } else { -not $ForceRenew }) } |
            Sort-Object Written -Descending | Select-Object -First 1)
        if ($reuse) {
            Write-Log "Reusing the certificate Posh-ACME issued on $($reuse[0].Written.ToString('yyyy-MM-dd HH:mm')) (expires $($reuse[0].Expires.ToString('yyyy-MM-dd'))): $($reuse[0].Path)" OK
            $ui.PfxPathBox.Text = $reuse[0].Path
            $ui.PfxPasswordBox.Password = $reuse[0].Password
            try { $null = Invoke-ValidatePfx } catch { Write-Log "The saved certificate could not be validated: $($_.Exception.Message)" WARN }
            if ($script:State.Validated -and $onIis -contains $script:State.NewThumb) {
                Write-Log "The saved certificate $($script:State.NewThumb) is the one already on IIS - not reused." WARN
                Reset-Validation
            }
            if (-not $script:State.Validated) { Write-Log 'The saved certificate is not usable - requesting a new one.' WARN }
        }
        if (-not $script:State.Validated) {
            Set-RenewalUi -Settings $settings
            $null = Start-LeRequest
            if (-not $Live) { Write-Log 'Dry run: stopped after the ACME step (nothing was requested). Steps A, B, C, Verify and removal run with -Live.' OK; $result = 'DRYRUN'; $script:RenewExitCode = 0; return }
        }
        if (-not $script:State.Validated) { throw 'The new certificate did not pass validation - see the log above.' }
        $blockers = @(Get-RenewalBlockers -OldIis $oldIis)
        if ($blockers) { throw "Stopped before changing Exchange: $($blockers -join ' | ')" }

        # Keep the decisions made in the GUI: only connectors pinned to the old certificate change (Step C);
        # POP/IMAP only if the old certificate served them.
        $ui.PinFrontendCheck.IsChecked = $false
        $ui.PinClientCheck.IsChecked = $false
        $oldThumbs = @($oldIis | ForEach-Object { $_.Thumbprint })
        $ui.PopImapCheck.IsChecked = [bool](@($script:State.Inventory | Where-Object { $_.Thumbprint -in $oldThumbs -and $_.Services -match 'POP|IMAP' }).Count)
        foreach ($step in @(@('Step A (import)', { Invoke-ImportCertificate }), @('Step B (enable)', { Invoke-EnableCertificate }), @('Step C (connectors)', { Invoke-UpdateConnectors }))) {
            $errorsBefore = $script:ErrorCount
            Write-Log "--- $($step[0]) ---"
            $null = & $step[1]
            if ($script:ErrorCount -gt $errorsBefore) { throw "$($step[0]) reported errors - stopped. The previous configuration is in the newest logs\Snapshot_*.json (GUI tab 3: Roll back)." }
        }
        if (-not $Live) { Write-Log 'Dry run: Steps A, B and C were logged above. Verify and removal run with -Live.' OK; $result = 'DRYRUN'; $script:RenewExitCode = 0; return }
        Write-Log '--- Verify ---'
        $null = Invoke-Verify
        $servers = @(Get-SelectedServers)
        if (@($servers | Where-Object { -not $script:State.Verified[$_] }).Count) {
            Write-Log 'Not every server serves the new certificate yet - checking again in 2 minutes.' WARN
            Wait-Ui 120
            $null = Invoke-Verify
        }
        $failed = @($servers | Where-Object { -not $script:State.Verified[$_] })
        if ($failed) { throw "Verification failed on $($failed -join ', '). The new certificate is enabled; check the HTTPS binding or run iisreset /noforce (GUI tab 4: Rolling restart)." }

        if ($RemoveOld) {
            Write-Log '--- Remove old certificate ---'
            $rows = @(Update-OldCandidates -PassThru | Where-Object { $_.Removable -eq 'yes' -and $_.Thumbprint -in $oldThumbs })
            if ($rows) { $null = Invoke-RemoveOld -Rows $rows } else { Write-Log 'No old certificate can be removed safely (see the Blockers in the log).' WARN }
        }
        else { Write-Log 'The old certificate is kept (-RemoveOld removes it after verification).' }
        $result = 'OK'
        $script:RenewExitCode = 0
        Write-Log 'Renewal completed.' OK
    }
    catch { Write-Log "Renewal FAILED: $($_.Exception.Message)" ERROR }
    finally { if ($result -ne 'NOTNEEDED') { Send-RenewalReport -Result $result } }
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
              <Button x:Name="RefreshButton" Content="Refresh certificate inventory" Margin="0,0,0,6"/>
              <Button x:Name="AuthRenewButton" Content="Renew / copy Auth certificate..." Margin="0,0,0,6"
                      ToolTip="Copies the Auth (OAuth) certificate to selected servers that miss it. When fewer than 60 days are left it creates a new one and schedules it (Exchange makes it current by itself in 49 hours); if it is expired, missing or has less than 3 days left, it replaces it immediately."/>
              <Button x:Name="AuthUploadButton" Content="Upload Auth certificate to Entra ID..." Margin="0"
                      ToolTip="Hybrid only: uploads the current (and next) Auth certificate to the dedicated Exchange hybrid app in Entra ID with Microsoft's ConfigureExchangeHybridApplication.ps1, in a new PowerShell window. Needed after the Auth certificate was renewed."/>
            </StackPanel>
            <ListBox x:Name="ServerList" SelectionMode="Multiple"/>
          </DockPanel>
          <DockPanel Grid.Column="1">
            <TextBlock DockPanel.Dock="Top" TextWrapping="Wrap" Foreground="DimGray"
                       Text="Read-only. Role column: Auth = OAuth certificate, InternalTransport = default SMTP certificate, NEW = the validated PFX. The log warns when the Auth certificate expires within 60 days or is missing on a server."/>
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
              <RadioButton x:Name="LeCfRadio" GroupName="LeMode" Margin="0,6,0,0" Content="DNS-01 automatic: Cloudflare (API token)"/>
              <StackPanel Margin="20,4,0,0">
                <TextBlock x:Name="LeCfDetectedText" Foreground="DarkGreen" TextWrapping="Wrap"/>
                <TextBlock TextWrapping="Wrap" Foreground="DimGray"
                           Text="Create a token at dash.cloudflare.com > My Profile > API Tokens > Create Token > template 'Edit zone DNS'. Permissions: Zone > DNS > Edit and Zone > Zone > Read, for your zone(s). Wildcards work. The token is never logged."/>
                <DockPanel Margin="0,4,0,0">
                  <Button x:Name="LeCfTestButton" DockPanel.Dock="Right" Content="Test Cloudflare token" Margin="8,0,0,0"/>
                  <PasswordBox x:Name="LeCfTokenBox"/>
                </DockPanel>
                <CheckBox x:Name="LeCfRememberCheck" Margin="0,4,0,0" Content="Remember the token for this Windows user (DPAPI-encrypted)"/>
              </StackPanel>
              <RadioButton x:Name="LeDnsPluginRadio" GroupName="LeMode" Margin="0,8,0,0" Content="DNS-01 automatic: other DNS provider (Posh-ACME plugin)"/>
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

      <TabItem Header="2. New certificate">
        <Grid Margin="8">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Grid.ColumnDefinitions><ColumnDefinition Width="110"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <TextBlock Text="PFX file:" VerticalAlignment="Center"/>
          <TextBox x:Name="PfxPathBox" Grid.Column="1" Margin="4"/>
          <Button x:Name="BrowseButton" Grid.Column="2" Content="Browse..." Margin="4"/>
          <TextBlock Grid.Row="1" Text="PFX password:" VerticalAlignment="Center"/>
          <PasswordBox x:Name="PfxPasswordBox" Grid.Row="1" Grid.Column="1" Margin="4"/>
          <WrapPanel Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="2">
            <Button x:Name="ValidateButton" Margin="4" Content="Validate certificate against Exchange (read-only)"/>
            <Button x:Name="LoadAcmeButton" Margin="4" Content="Load last Let's Encrypt/ACME certificate"/>
          </WrapPanel>
          <TextBlock Grid.Row="3" Text="Or installed:" VerticalAlignment="Center" ToolTip="Use a certificate that is already in Exchange / bound to IIS - no PFX needed"/>
          <DockPanel Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="2" Margin="0,4,0,0">
            <Button x:Name="UseInstalledButton" DockPanel.Dock="Right" Margin="4" Content="Use installed certificate"/>
            <Button x:Name="RefreshInstalledButton" DockPanel.Dock="Right" Margin="4" Content="Refresh"/>
            <ComboBox x:Name="InstalledCertCombo" Margin="4" FontFamily="Consolas"/>
          </DockPanel>
          <TextBlock Grid.Row="4" Text="Or CSR:" VerticalAlignment="Center" ToolTip="Commercial or internal CA (AD CS): create a request on the first selected server, then import the issued certificate"/>
          <WrapPanel Grid.Row="4" Grid.Column="1" Grid.ColumnSpan="2" Margin="0,4,0,0">
            <Button x:Name="CsrCreateButton" Margin="4" Content="Create CSR (names from tab 1b)..."/>
            <Button x:Name="CsrCompleteButton" Margin="4" Content="Complete pending request (.cer / .p7b)..."/>
          </WrapPanel>
          <TextBox x:Name="ValidationBox" Grid.Row="5" Grid.ColumnSpan="3" Margin="0,8,0,0" IsReadOnly="True" FontFamily="Consolas"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"/>
        </Grid>
      </TabItem>

      <TabItem Header="3. Import &amp; enable">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel Margin="12">
          <TextBlock TextWrapping="Wrap" Text="Step A imports the validated PFX into every selected server (the same PFX on each server, so all get the identical certificate and private key). Step B enables it for IIS and SMTP. The Exchange Back End website (port 444) keeps its self-signed certificate. Nothing is removed here - the old certificate stays until tab 5."/>
          <CheckBox x:Name="ExportableCheck" Margin="0,14,0,0" Content="Mark private key as exportable on the servers (only if you need to export it from Exchange later)"/>
          <CheckBox x:Name="ReplaceInternalCheck" Margin="0,6,0,0" Content="Also replace the internal transport (default SMTP) certificate - normally leave unchecked"/>
          <CheckBox x:Name="PopImapCheck" Margin="0,6,0,0" Content="Also enable it for POP3 and IMAP4 (only if clients use them: sets X509CertificateName if needed and restarts the POP/IMAP services)"/>
          <StackPanel Orientation="Horizontal" Margin="0,18,0,0">
            <Button x:Name="ImportButton" Content="Step A: Import PFX to selected servers"/>
            <Button x:Name="EnableButton" Content="Step B: Enable for IIS + SMTP"/>
          </StackPanel>
          <TextBlock Margin="0,18,0,0" TextWrapping="Wrap" Foreground="DimGray"
                     Text="Recommended: run every step once with 'Dry run' ticked and read the log, then untick 'Dry run' and run them for real."/>
          <TextBlock Margin="0,22,0,4" FontWeight="Bold" Text="Step C: SMTP connectors (TlsCertificateName)"/>
          <TextBlock TextWrapping="Wrap" Foreground="DimGray"
                     Text="Updates Send/Receive connectors and the hybrid configuration (HCW) that are pinned to the old certificate (e.g. hybrid 'Outbound to Office 365' and 'Default Frontend' set by the HCW), and can pin the new certificate on the frontend receive connectors. Without a pinned certificate, the 'Default Frontend' connector offers the certificate that matches its FQDN - usually the server's self-signed one - to internet senders. The connector FQDN is never changed (that can break Kerberos between Exchange servers). Run after Step B."/>
          <CheckBox x:Name="PinFrontendCheck" Margin="0,8,0,0" IsChecked="True" Content="Pin the new certificate on 'Default Frontend' receive connectors (port 25, internet mail / STARTTLS)"/>
          <CheckBox x:Name="PinClientCheck" Margin="0,4,0,0" Content="Also pin it on 'Client Frontend' receive connectors (port 587, authenticated SMTP submission)"/>
          <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
            <Button x:Name="ConnectorPreviewButton" Content="Preview connector changes"/>
            <Button x:Name="ConnectorUpdateButton" Content="Step C: Update connectors"/>
          </StackPanel>
          <DataGrid x:Name="ConnectorGrid" Height="190"/>
          <TextBlock Margin="0,22,0,4" FontWeight="Bold" Text="Step D: Exchange Online connectors (hybrid, optional)"/>
          <TextBlock TextWrapping="Wrap" Foreground="DimGray"
                     Text="Exchange Online checks your certificate by name only (inbound connector TlsSenderCertificateName, outbound connector TlsDomain). With the same names nothing changes there - no Hybrid Configuration Wizard run needed. If the names changed, Step D sets them to the new certificate's name right after Step C. Needs the ExchangeOnlineManagement module and an Exchange administrator sign-in."/>
          <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
            <Button x:Name="ExoCheckButton" Content="Check Exchange Online connectors"/>
            <Button x:Name="ExoUpdateButton" Content="Step D: Update Exchange Online connectors"/>
          </StackPanel>
          <DataGrid x:Name="ExoGrid" Height="110"/>
          <TextBlock Margin="0,22,0,4" FontWeight="Bold" Text="Roll back / Edge Transport / HAProxy"/>
          <TextBlock TextWrapping="Wrap" Foreground="DimGray"
                     Text="Steps B and C first save the current configuration to logs\Snapshot_*.json. Roll back restores the IIS certificate (also a self-signed one), internal transport certificate, connector and hybrid TlsCertificateName and POP/IMAP names from a snapshot (the old certificate must still be installed). The Edge and HAProxy packages are folders with the PFX and an install script for Edge Transport servers and for an HAProxy that terminates TLS - this tool cannot reach either."/>
          <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
            <Button x:Name="RollbackButton" Content="Roll back from snapshot..."/>
            <Button x:Name="EdgePackageButton" Content="Create Edge Transport package..."/>
            <Button x:Name="HaproxyPackageButton" Content="Create HAProxy package..."/>
          </StackPanel>
        </StackPanel>
        </ScrollViewer>
      </TabItem>

      <TabItem Header="4. Verify">
        <DockPanel Margin="8">
          <StackPanel DockPanel.Dock="Top">
            <TextBlock Text="Extra TLS endpoints to probe, e.g. load balancer / public name (host or host:port, comma-separated):"/>
            <DockPanel Margin="0,4,0,0">
              <Button x:Name="RestartButton" DockPanel.Dock="Right" Margin="8,0,0,0" Content="Rolling restart..."
                      ToolTip="iisreset /noforce and restart Frontend Transport, one server at a time, waiting for port 443 between servers"/>
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

$script:ActionButtons = 'ReloadServersButton', 'RefreshButton', 'BrowseButton', 'ValidateButton', 'LoadAcmeButton', 'UseInstalledButton', 'RefreshInstalledButton', 'ImportButton', 'EnableButton', 'ConnectorPreviewButton', 'ConnectorUpdateButton', 'VerifyButton', 'LoadOldButton', 'RemoveButton',
'AuthRenewButton', 'CsrCreateButton', 'CsrCompleteButton', 'RollbackButton', 'EdgePackageButton', 'HaproxyPackageButton', 'AuthUploadButton', 'ExoCheckButton', 'ExoUpdateButton', 'RestartButton',
'LeInstallModuleButton', 'LeRecheckModuleButton', 'LeZeroSslEabButton', 'LeCfTestButton', 'LeFillCertButton', 'LeFillNamesButton', 'LePluginParamsButton', 'LeTestHttpButton', 'LeRequestButton', 'LeCheckDnsButton', 'LeContinueButton', 'LeCleanupButton'

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
    $ui.LoadAcmeButton.Add_Click({ Invoke-UiAction 'Load ACME certificate' { Invoke-LoadAcmeSaved } })
    $ui.UseInstalledButton.Add_Click({ Invoke-UiAction 'Use installed certificate' { Invoke-UseInstalledCertificate } })
    $ui.RefreshInstalledButton.Add_Click({ Invoke-UiAction 'Refresh installed certificates' { Update-InventoryAndInstalled } })
    $ui.PfxPasswordBox.Add_PasswordChanged({ Reset-Validation })
    $ui.ValidateButton.Add_Click({ Invoke-UiAction 'Validate' { Invoke-ValidatePfx } })
    $ui.ImportButton.Add_Click({ Invoke-UiAction 'Import' { Invoke-ImportCertificate } })
    $ui.EnableButton.Add_Click({ Invoke-UiAction 'Enable' { Invoke-EnableCertificate } })
    $ui.ConnectorPreviewButton.Add_Click({ Invoke-UiAction 'Connector preview' { Update-ConnectorPreview } })
    $ui.ConnectorUpdateButton.Add_Click({ Invoke-UiAction 'Update connectors' { Invoke-UpdateConnectors } })
    $ui.VerifyButton.Add_Click({ Invoke-UiAction 'Verify' { Invoke-Verify } })
    $ui.LoadOldButton.Add_Click({ Invoke-UiAction 'Load candidates' { Update-OldCandidates } })
    $ui.RemoveButton.Add_Click({ Invoke-UiAction 'Remove' { Invoke-RemoveOld } })
    $ui.AuthRenewButton.Add_Click({ Invoke-UiAction 'Auth certificate' { Invoke-AuthCertificate } })
    $ui.AuthUploadButton.Add_Click({ Invoke-UiAction 'Upload Auth certificate' { Invoke-UploadAuthToEntra } })
    $ui.ExoCheckButton.Add_Click({ Invoke-UiAction 'Exchange Online connectors' { [void](Get-ExoConnectorPlanLive) } })
    $ui.ExoUpdateButton.Add_Click({ Invoke-UiAction 'Step D' { Invoke-UpdateExoConnectors } })
    $script:Window.Add_Closed({ if ($script:ExoConnectedByTool) { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop } catch { } } })
    $ui.CsrCreateButton.Add_Click({ Invoke-UiAction 'Create CSR' { New-CertificateRequest } })
    $ui.CsrCompleteButton.Add_Click({ Invoke-UiAction 'Complete pending request' { Complete-CertificateRequest } })
    $ui.RollbackButton.Add_Click({ Invoke-UiAction 'Roll back' { Invoke-Rollback } })
    $ui.EdgePackageButton.Add_Click({ Invoke-UiAction 'Edge package' { New-EdgePackage } })
    $ui.HaproxyPackageButton.Add_Click({ Invoke-UiAction 'HAProxy package' { New-HaproxyPackage } })
    $ui.RestartButton.Add_Click({ Invoke-UiAction 'Rolling restart' { Invoke-RollingRestart } })
    $ui.LeInstallModuleButton.Add_Click({ Invoke-UiAction 'Install Posh-ACME' { Install-PoshAcme } })
    $ui.LeFillNamesButton.Add_Click({ Invoke-UiAction 'Fill names' { Set-LeNamesFromExchange } })
    $ui.LeFillCertButton.Add_Click({ Invoke-UiAction 'Fill from certificate' { [void](Set-LeNamesFromCurrentCert) } })
    foreach ($pr in $script:AcmeProviders) { [void]$ui.LeProviderCombo.Items.Add($pr.Label) }
    $ui.LeProviderCombo.SelectedIndex = 0
    Update-AcmeProviderUi
    $ui.LeProviderCombo.Add_SelectionChanged({ Update-AcmeProviderUi })
    $ui.LeZeroSslEabButton.Add_Click({ Invoke-UiAction 'ZeroSSL EAB' { Get-ZeroSslEab } })
    $ui.LeCfTestButton.Add_Click({ Invoke-UiAction 'Cloudflare test' { $script:ui.LeCfRadio.IsChecked = $true; [void](Test-CloudflareSetup) } })
    $ui.LeCfTokenBox.Add_PasswordChanged({ if ($script:ui.LeCfTokenBox.Password) { $script:ui.LeCfRadio.IsChecked = $true } })
    Restore-CfToken
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
            if (Test-ExchangeAvailable) { Invoke-UiAction 'Load servers' { Update-ServerList; Update-Inventory; Update-InstalledCertList; Invoke-LeAutoFill } }
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

if ($Renew) {
    Invoke-UnattendedRenewal
    Write-Log "Renewal run finished (exit code $script:RenewExitCode). Log: $script:LogFile"
    exit $script:RenewExitCode
}

New-MainWindow
$script:ui.LogBox.Text = (Get-Content -LiteralPath $script:LogFile -Raw)
Register-UiEvents
Update-ModeBanner
[void]$script:Window.ShowDialog()
Write-Log 'Tool closed.'
