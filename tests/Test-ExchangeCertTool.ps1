#Requires -Version 5.1
<#
    Offline self-check for ExchangeCertTool.ps1. Needs no Exchange and changes nothing:
    the Exchange cmdlets are mocked, DNS lookups are mocked, no certificate or private key is created
    (the X509 tests use public certificates from the local Trusted Root store, read-only).

        powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\tests\Test-ExchangeCertTool.ps1

    Exit code 0 = all checks passed.
#>
$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot '..\ExchangeCertTool.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('certtool-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
$script:Failures = 0
function Assert-That([string]$Name, [bool]$Ok) {
    if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:Failures++ }
}

# ---------------------------------------------------------------------------------------------
# Fake Exchange organisation: EX01 + EX02, old Let's Encrypt certificate on IIS, hybrid pinned to it
# ---------------------------------------------------------------------------------------------
$oldTls = "<I>CN=R11, O=Let's Encrypt, C=US<S>CN=mail.contoso.com"
function New-MockCert($Thumb, $Subject, $Issuer, $Services, $Days, [bool]$SelfSigned = $false, [string[]]$Domains = @()) {
    [pscustomobject]@{ Thumbprint = $Thumb; Subject = $Subject; Issuer = $Issuer; Services = $Services; NotAfter = (Get-Date).AddDays($Days)
        IsSelfSigned = $SelfSigned; CertificateDomains = $Domains; Status = 'Valid'; PrivateKeyExportable = $true; HasPrivateKey = $true }
}
function Reset-MockOrg {
    $global:Calls = New-Object System.Collections.Generic.List[string]
    $global:Org = @{
        Certs      = @{}
        Transport  = @{ EX01 = 'SELF1'; EX02 = 'SELF2' }
        Auth       = 'AUTH1'
        Send       = @([pscustomobject]@{ Identity = 'Outbound to Office 365'; TlsCertificateName = $oldTls; SourceTransportServers = @('EX01', 'EX02'); Fqdn = 'mail.contoso.com' })
        Receive    = @{}
        Hybrid     = $oldTls
        Pop        = @{ EX01 = 'mail.contoso.com'; EX02 = 'mail.contoso.com' }
        NewCert    = (New-MockCert 'NEW1' 'CN=mail.contoso.com' "CN=R12, O=Let's Encrypt, C=US" 'None' 89 $false @('mail.contoso.com', 'autodiscover.contoso.com'))
    }
    foreach ($s in 'EX01', 'EX02') {
        $Org.Certs[$s] = New-Object System.Collections.ArrayList   # List[object] breaks @() on PowerShell 5.1 build 26100
        [void]$Org.Certs[$s].Add((New-MockCert 'OLD1' 'CN=mail.contoso.com' "CN=R11, O=Let's Encrypt, C=US" 'IIS, SMTP' 10 $false @('mail.contoso.com', 'autodiscover.contoso.com')))
        [void]$Org.Certs[$s].Add((New-MockCert "SELF$($s.Substring(3))" "CN=$s" "CN=$s" 'IIS, SMTP' 1500 $true @($s.ToLower())))
        [void]$Org.Certs[$s].Add((New-MockCert 'AUTH1' 'CN=Microsoft Exchange Server Auth Certificate' 'CN=Microsoft Exchange Server Auth Certificate' 'SMTP' 1000 $true))
        [void]$Org.Certs[$s].Add((New-MockCert 'OTHER1' 'CN=legacy.contoso.com' 'CN=Some CA' 'None' 200 $false @('legacy.contoso.com')))
        $Org.Receive[$s] = @(
            [pscustomobject]@{ Identity = "$s\Default Frontend $s"; TlsCertificateName = $(if ($s -eq 'EX01') { $oldTls } else { $null }); Bindings = @('0.0.0.0:25'); TransportRole = 'FrontendTransport'; Fqdn = "$($s.ToLower()).contoso.local" }
            [pscustomobject]@{ Identity = "$s\Client Frontend $s"; TlsCertificateName = $null; Bindings = @('0.0.0.0:587'); TransportRole = 'FrontendTransport'; Fqdn = "$($s.ToLower()).contoso.local" }
        )
    }
}
Reset-MockOrg

function global:Get-ExchangeServer { 'EX01', 'EX02' | ForEach-Object { [pscustomobject]@{ Name = $_; Fqdn = "$($_.ToLower()).contoso.local"; ServerRole = 'Mailbox'; AdminDisplayVersion = 'Version 15.2 (Build 1544.4)' } } }
function global:Get-AuthConfig { [pscustomobject]@{ CurrentCertificateThumbprint = $Org.Auth; PreviousCertificateThumbprint = $null; NextCertificateThumbprint = $null; NextCertificateEffectiveDate = $null } }
function global:Get-TransportService { [CmdletBinding()] param($Identity) [pscustomobject]@{ InternalTransportCertificateThumbprint = $Org.Transport["$Identity"] } }
function global:Set-TransportService { [CmdletBinding()] param($Identity, $InternalTransportCertificateThumbprint) $Calls.Add("Set-TransportService $Identity"); $Org.Transport["$Identity"] = $InternalTransportCertificateThumbprint }
function global:Get-ExchangeCertificate {
    [CmdletBinding()] param($Server, $Thumbprint)
    $list = @($Org.Certs["$Server"])
    if ($Thumbprint) { $c = $list | Where-Object { $_.Thumbprint -eq $Thumbprint }; if (-not $c) { throw "certificate $Thumbprint not found on $Server" }; return $c }
    $list
}
function global:Import-ExchangeCertificate {
    [CmdletBinding()] param($Server, $FileData, $Password, $PrivateKeyExportable)
    $Calls.Add("Import-ExchangeCertificate $Server")
    $c = $Org.NewCert.PSObject.Copy(); [void]$Org.Certs["$Server"].Add($c); $c
}
function global:Enable-ExchangeCertificate {
    [CmdletBinding()] param($Server, $Thumbprint, $Services, [switch]$Force)
    $Calls.Add("Enable-ExchangeCertificate $Server $Thumbprint $($Services -join ',')")
    foreach ($c in $Org.Certs["$Server"]) {
        if ($c.Thumbprint -eq $Thumbprint) { $c.Services = (@(("$($c.Services)" -split '\s*,\s*') + @($Services) | Where-Object { $_ -and $_ -ne 'None' } | Select-Object -Unique) -join ', ') }
        elseif (@($Services) -contains 'IIS' -and -not $c.IsSelfSigned) { $c.Services = (@(("$($c.Services)" -split '\s*,\s*') | Where-Object { $_ -ne 'IIS' }) -join ', ') }
    }
}
function global:Remove-ExchangeCertificate { [CmdletBinding(SupportsShouldProcess)] param($Server, $Thumbprint) $Calls.Add("Remove-ExchangeCertificate $Server $Thumbprint"); $Org.Certs["$Server"].Remove(($Org.Certs["$Server"] | Where-Object { $_.Thumbprint -eq $Thumbprint })) }
function global:Export-ExchangeCertificate { [CmdletBinding()] param($Server, $Thumbprint, [switch]$BinaryEncoded, $Password) $Calls.Add("Export-ExchangeCertificate $Server"); [byte[]](1..200) }
function global:New-ExchangeCertificate { [CmdletBinding()] param() $Calls.Add('New-ExchangeCertificate') }
function global:Set-AuthConfig { [CmdletBinding(SupportsShouldProcess)] param() $Calls.Add('Set-AuthConfig') }
function global:Get-SendConnector { [CmdletBinding()] param($Identity) if ($Identity) { $Org.Send | Where-Object { $_.Identity -eq "$Identity" } } else { $Org.Send } }
function global:Set-SendConnector { [CmdletBinding()] param($Identity, $TlsCertificateName) $Calls.Add("Set-SendConnector $Identity"); ($Org.Send | Where-Object { $_.Identity -eq "$Identity" }).TlsCertificateName = $TlsCertificateName }
function global:Get-ReceiveConnector {
    [CmdletBinding()] param($Server, $Identity)
    if ($Identity) { return ($Org.Receive.Values | ForEach-Object { $_ } | Where-Object { $_.Identity -eq "$Identity" }) }
    $Org.Receive["$Server"]
}
function global:Set-ReceiveConnector { [CmdletBinding()] param($Identity, $TlsCertificateName) $Calls.Add("Set-ReceiveConnector $Identity"); ($Org.Receive.Values | ForEach-Object { $_ } | Where-Object { $_.Identity -eq "$Identity" }).TlsCertificateName = $TlsCertificateName }
function global:Get-HybridConfiguration { [CmdletBinding()] param() if ($null -ne $Org.Hybrid) { [pscustomobject]@{ TlsCertificateName = $Org.Hybrid } } }
function global:Set-HybridConfiguration { [CmdletBinding()] param($TlsCertificateName) $Calls.Add('Set-HybridConfiguration'); $Org.Hybrid = $TlsCertificateName }
function global:Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'contoso.com'; DomainType = 'Authoritative'; Default = $true }; [pscustomobject]@{ DomainName = 'fabrikam.com'; DomainType = 'Authoritative'; Default = $false } }
function global:Get-PopSettings { [CmdletBinding()] param($Server) [pscustomobject]@{ X509CertificateName = $Org.Pop["$Server"] } }
function global:Get-ImapSettings { [CmdletBinding()] param($Server) [pscustomobject]@{ X509CertificateName = $Org.Pop["$Server"] } }
function global:Set-PopSettings { [CmdletBinding()] param($Server, $X509CertificateName) $Calls.Add("Set-PopSettings $Server"); $Org.Pop["$Server"] = $X509CertificateName }
function global:Set-ImapSettings { [CmdletBinding()] param($Server, $X509CertificateName) $Calls.Add("Set-ImapSettings $Server"); $Org.Pop["$Server"] = $X509CertificateName }
function global:Get-ClientAccessService { [CmdletBinding()] param($Identity) [pscustomobject]@{ AutoDiscoverServiceInternalUri = 'https://autodiscover.contoso.com/Autodiscover/Autodiscover.xml' } }
foreach ($v in 'Owa', 'Ecp', 'WebServices', 'Oab', 'ActiveSync', 'Mapi') {
    Set-Item -Path "function:global:Get-${v}VirtualDirectory" -Value { [CmdletBinding()] param($Server, [switch]$ADPropertiesOnly) [pscustomobject]@{ InternalUrl = 'https://mail.contoso.com/x'; ExternalUrl = 'https://mail.contoso.com/x' } }
}

# ---------------------------------------------------------------------------------------------
# Load the tool (functions + hidden window)
# ---------------------------------------------------------------------------------------------
. $tool -LoadOnly -LogDirectory $tmp
$script:Unattended = $true          # confirmations are automatic, no message boxes
$script:CfTokenFile = Join-Path $tmp 'cf.dpapi'
$script:RenewalProfileFile = Join-Path $tmp 'renewal.json'
$env:POSHACME_HOME = Join-Path $tmp 'pa'   # empty: keeps the real Posh-ACME folder out of the tests
New-Item -ItemType Directory -Path $env:POSHACME_HOME | Out-Null
$logText = { Get-Content -LiteralPath $script:LogFile -Raw }
$script:RealFindAcme = ${function:Find-AcmeSavedCertificates}   # kept before a test replaces it with a mock

# DNS is mocked: contoso.com MX = mail.contoso.com (these servers), fabrikam.com MX = old.fabrikam.com
$script:MockTlsa = @{}
function Resolve-PublicName { param($Name, $Type) switch ($Name) { 'contoso.com' { [pscustomobject]@{ Type = 'MX'; NameExchange = 'mail.contoso.com' } } 'fabrikam.com' { [pscustomobject]@{ Type = 'MX'; NameExchange = 'contoso-com.mail.protection.outlook.com' } } } }
function Get-PublicTlsa { param($Name) if ($script:MockTlsa.ContainsKey($Name)) { return , @($script:MockTlsa[$Name]) }; , @() }
function Get-RemoteTlsCertificate { param($HostName, $Port, $SniName, [switch]$StartTls, $TimeoutMs) $s = ($HostName -split '\.')[0].ToUpper(); $iis = $Org.Certs[$s] | Where-Object { -not $_.IsSelfSigned -and $_.Services -match 'IIS' } | Select-Object -First 1; [pscustomobject]@{ Thumbprint = $iis.Thumbprint; Subject = $iis.Subject; NotAfter = $iis.NotAfter; Protocol = 'Tls12' } }

# ---------------------------------------------------------------------------------------------
# Window and plumbing
# ---------------------------------------------------------------------------------------------
Assert-That 'window builds and every action button exists' (@($script:ActionButtons | Where-Object { -not $script:ui[$_] }).Count -eq 0)
Assert-That 'new option controls exist' ([bool]($script:ui.PopImapCheck -and $script:ui.AuthRenewButton -and $script:ui.RestartButton -and $script:ui.CsrCreateButton))
Assert-That 'Write-Log writes nothing to the pipeline' (@(Write-Log 'pipeline test').Count -eq 0)
Update-ServerList
Assert-That 'hidden ListBox: all servers selected' (@(Get-SelectedServers).Count -eq 2)
$script:ui.ServerList.SelectedItems.Clear(); [void]$script:ui.ServerList.SelectedItems.Add('EX02')
Assert-That 'hidden ListBox: selection by name' ((@(Get-SelectedServers) -join ',') -eq 'EX02')
$script:ui.ServerList.SelectAll()

# ---------------------------------------------------------------------------------------------
# DER / DANE helpers against public root certificates (read-only)
# ---------------------------------------------------------------------------------------------
function Get-DerTlv([int]$Tag, [byte[]]$Content) {
    $n = $Content.Length
    $len = if ($n -lt 128) { @($n) } elseif ($n -lt 256) { @(0x81, $n) } else { @(0x82, ($n -shr 8), ($n -band 255)) }
    , [byte[]](@($Tag) + $len + $Content)
}
$roots = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1' -and (ConvertTo-HexString $_.PublicKey.EncodedParameters.RawData) -eq '0500' } | Select-Object -First 15)
$spkiOk = $roots.Count -gt 0
foreach ($r in $roots) {
    $alg = Get-DerTlv 0x30 ([byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00))
    $expected = Get-DerTlv 0x30 ([byte[]]($alg + (Get-DerTlv 0x03 ([byte[]](@(0) + $r.PublicKey.EncodedKeyValue.RawData)))))
    if ((ConvertTo-HexString (Get-CertSpki $r)) -ne (ConvertTo-HexString $expected)) { $spkiOk = $false; Write-Host "  SPKI mismatch: $($r.Subject)" }
}
Assert-That "Get-CertSpki matches an independently built SPKI ($($roots.Count) RSA root certificates)" $spkiOk

$leafCert = $roots[0]; $caCert = $roots[1]
$sha = { param([byte[]]$b) ConvertTo-HexString ([System.Security.Cryptography.SHA256]::Create().ComputeHash($b)) }
$spkiHash = & $sha (Get-CertSpki $leafCert)
Assert-That 'TLSA parse: Google format' ((ConvertFrom-TlsaData "3 1 1 $($spkiHash.ToLower())").Data -eq $spkiHash)
Assert-That 'TLSA parse: Cloudflare format' ((ConvertFrom-TlsaData "3 1 1 ( $spkiHash )").Data -eq $spkiHash)
Assert-That 'TLSA parse: RFC 3597 format' ((ConvertFrom-TlsaData "\# 35 030101$spkiHash").MatchType -eq 1)
Assert-That 'TLSA 3 1 1 matches the leaf' (Test-TlsaMatch -Record (ConvertFrom-TlsaData "3 1 1 $spkiHash") -Leaf $leafCert -CaCerts @())
Assert-That 'TLSA 3 1 1 of another key does not match' (-not (Test-TlsaMatch -Record (ConvertFrom-TlsaData "3 1 1 $(& $sha (Get-CertSpki $caCert))") -Leaf $leafCert -CaCerts @()))
Assert-That 'TLSA 2 0 1 matches a CA of the chain' (Test-TlsaMatch -Record (ConvertFrom-TlsaData "2 0 1 $(& $sha $caCert.RawData)") -Leaf $leafCert -CaCerts @($caCert))
Assert-That 'TLSA 3 0 2 (SHA-512 of the certificate) matches' (Test-TlsaMatch -Record (ConvertFrom-TlsaData "3 0 2 $(ConvertTo-HexString ([System.Security.Cryptography.SHA512]::Create().ComputeHash($leafCert.RawData)))") -Leaf $leafCert -CaCerts @())

# ---------------------------------------------------------------------------------------------
# Inventory: Auth certificate checks
# ---------------------------------------------------------------------------------------------
$Org.Certs['EX02'].Remove(($Org.Certs['EX02'] | Where-Object { $_.Thumbprint -eq 'AUTH1' })) | Out-Null
($Org.Certs['EX01'] | Where-Object { $_.Thumbprint -eq 'AUTH1' }).NotAfter = (Get-Date).AddDays(30)
Update-Inventory
$log = & $logText
Assert-That 'Auth: missing server is reported' ($log -match 'Auth \(OAuth\) certificate AUTH1 is missing on EX02')
Assert-That 'Auth: expiry within 60 days is reported' ($log -match 'Renew it soon')
$Calls.Clear()
$script:ui.DryRunCheck.IsChecked = $true
Invoke-AuthCertificate
Assert-That 'Auth renewal (dry run) logs New-ExchangeCertificate and changes nothing' (((& $logText) -match "\[DRY RUN\] New-ExchangeCertificate -Server EX0[12] .*-SubjectName 'cn=Microsoft Exchange Server Auth Certificate'") -and $Calls.Count -eq 0)
($Org.Certs['EX01'] | Where-Object { $_.Thumbprint -eq 'AUTH1' }).NotAfter = (Get-Date).AddDays(900)
Invoke-AuthCertificate
Assert-That 'Auth copy (dry run) when only a server misses it' (((& $logText) -match '\[DRY RUN\] Export-ExchangeCertificate -Server EX01 -Thumbprint AUTH1') -and $Calls.Count -eq 0)
# Get-AuthConfig failing must not look like "no Auth certificate" (that would replace a working one)
$realAuthConfig = ${function:global:Get-AuthConfig}
function global:Get-AuthConfig { [CmdletBinding()] param() throw 'session lost' }
$script:ui.DryRunCheck.IsChecked = $false
$Calls.Clear(); $e = $null
try { Invoke-AuthCertificate } catch { $e = $_.Exception.Message }
Assert-That 'Auth: Get-AuthConfig failure stops the button, nothing created' ($e -match 'Get-AuthConfig did not answer' -and @($Calls -like 'New-ExchangeCertificate*').Count -eq 0 -and @($Calls -like 'Set-AuthConfig*').Count -eq 0)
Set-Item -Path function:global:Get-AuthConfig -Value $realAuthConfig
$script:ui.DryRunCheck.IsChecked = $true
Reset-MockOrg
Update-Inventory

# ---------------------------------------------------------------------------------------------
# Mail flow checks (hybrid name, MX dropped, DANE)
# ---------------------------------------------------------------------------------------------
$sb = New-Object System.Text.StringBuilder; $w = New-Object System.Collections.Generic.List[string]
$script:State.BlockingIssues = @()
$Org.Hybrid = '<I>CN=R11, O=Let''s Encrypt, C=US<S>CN=hybrid.contoso.com'
$script:MockTlsa['_25._tcp.mail.contoso.com'] = @(ConvertFrom-TlsaData "3 1 1 $(& $sha (Get-CertSpki $caCert))")
Add-MailFlowChecks -Report $sb -Warnings $w -Leaf $leafCert -Names @('mail.contoso.com')
$bi = @($script:State.BlockingIssues) -join ' | '
Assert-That 'blocks: hybrid name not on the new certificate' ($bi -match 'Hybrid: the new certificate does not contain hybrid\.contoso\.com')
Assert-That 'blocks: DANE record does not match the new certificate' ($bi -match "DANE: no TLSA record of _25\._tcp\.mail\.contoso\.com.*3 1 1 $spkiHash")
Assert-That 'no MX block while the MX name stays on the certificate' (@($script:State.BlockingIssues | Where-Object { $_ -like 'MX mail.contoso.com*' }).Count -eq 0)
$sb = New-Object System.Text.StringBuilder; $w = New-Object System.Collections.Generic.List[string]; $script:State.BlockingIssues = @()
Add-MailFlowChecks -Report $sb -Warnings $w -Leaf $leafCert -Names @('autodiscover.contoso.com')
Assert-That 'blocks: MX name dropped from the certificate' (@($script:State.BlockingIssues | Where-Object { $_ -like 'MX mail.contoso.com (contoso.com) is on the current certificate*' }).Count -eq 1)
$sb = New-Object System.Text.StringBuilder; $w = New-Object System.Collections.Generic.List[string]; $script:State.BlockingIssues = @()
$Org.Hybrid = $oldTls
$script:MockTlsa['_25._tcp.mail.contoso.com'] = @(ConvertFrom-TlsaData "3 1 1 $spkiHash")
Add-MailFlowChecks -Report $sb -Warnings $w -Leaf $leafCert -Names @('mail.contoso.com', 'autodiscover.contoso.com')
Assert-That 'no blocking issue when hybrid name, MX and DANE match' (@($script:State.BlockingIssues).Count -eq 0)
Assert-That 'report shows the DANE match' ($sb.ToString() -match 'DANE: a TLSA record of _25\._tcp\.mail\.contoso\.com matches')
$script:MockTlsa.Clear()

Update-InstalledCertList
$script:ui.InstalledCertCombo.SelectedIndex = [array]::IndexOf(@($script:InstalledChoices | ForEach-Object { $_.Thumbprint }), 'OLD1')
Invoke-UseInstalledCertificate
Assert-That 'installed certificate path: validates and runs the mail flow checks' ($script:State.Validated -and $script:State.NewThumb -eq 'OLD1' -and $script:ui.ValidationBox.Text -match '=== MAIL FLOW' -and $script:ui.ValidationBox.Text -match 'EKU and DANE checks skipped')
Reset-Validation

$script:State.MissingHosts = @('mail.contoso.com', 'ex01.contoso.local')
$script:State.BlockingIssues = @()
$blk = @(Get-RenewalBlockers -OldIis @(Get-CurrentIisCertificates))
Assert-That 'renewal blocker: a name the old certificate covered is missing' (($blk -join '|') -match 'does not cover mail\.contoso\.com' -and ($blk -join '|') -notmatch 'ex01\.contoso\.local')
$script:State.MissingHosts = @()

# ---------------------------------------------------------------------------------------------
# Renewal settings round trip
# ---------------------------------------------------------------------------------------------
$script:Le.UiMode = 'DNSPlugin'; $script:Le.Plugin = 'Route53'; $script:Le.Names = @('mail.contoso.com', 'autodiscover.contoso.com')
$script:Le.Provider = $script:AcmeProviders | Where-Object { $_.Server -eq 'LE_PROD' }
$script:ui.LePluginArgsBox.Text = "R53AccessKey=AKIA123`r`nR53SecretKey=secure:topsecret"
Save-RenewalProfile
$saved = Get-Content -LiteralPath $script:RenewalProfileFile -Raw
Assert-That 'renewal settings do not contain the plugin secret in clear text' ($saved -notmatch 'topsecret' -and $saved -notmatch 'AKIA123')
$script:ui.LePluginArgsBox.Text = ''; $script:ui.LeNamesBox.Text = ''
Set-RenewalUi -Settings (Get-RenewalProfile)
Assert-That 'renewal settings restore names, plugin and DPAPI arguments' ($script:ui.LeNamesBox.Text -match 'autodiscover\.contoso\.com' -and $script:ui.LeDnsPluginRadio.IsChecked -and $script:ui.LePluginArgsBox.Text -match 'secure:topsecret' -and (Get-AcmeProvider).Server -eq 'LE_PROD')

# ---------------------------------------------------------------------------------------------
# Unattended renewal, dry run: stops after the (dry) ACME step and changes nothing
# ---------------------------------------------------------------------------------------------
[ordered]@{ Version = 1; Saved = (Get-Date).ToString('s'); User = 'TEST\admin'; Provider = 'LE_PROD'; Names = @('mail.contoso.com', 'autodiscover.contoso.com')
    Mode = 'HTTP'; Plugin = ''; PluginArgs = ''; Webroot = (Join-Path $tmp 'webroot'); KeyLength = '2048'; Email = ''; Servers = @('EX01', 'EX02') } |
    ConvertTo-Json | Set-Content -LiteralPath $script:RenewalProfileFile -Encoding UTF8
$Live = $false; $RemoveOld = $false; $ForceRenew = $false; $RenewDays = 30
$Calls.Clear()
Invoke-UnattendedRenewal
Assert-That 'renew dry run: exit code 0, nothing changed' ($script:RenewExitCode -eq 0 -and $Calls.Count -eq 0 -and ((& $logText) -match 'Dry run: stopped after the ACME step'))

# ---------------------------------------------------------------------------------------------
# Unattended renewal, "live" against the mocks, reusing a certificate Posh-ACME already issued
# ---------------------------------------------------------------------------------------------
$dummyPfx = Join-Path $tmp 'fullchain.pfx'; [IO.File]::WriteAllBytes($dummyPfx, [byte[]](1..64))
function Find-AcmeSavedCertificates { [pscustomobject]@{ Path = $dummyPfx; Password = 'x'; MainDomain = 'mail.contoso.com'; Expires = (Get-Date).AddDays(89); Written = (Get-Date); Server = 'acme-v02.api.letsencrypt.org' } }
function Invoke-ValidatePfx {
    Reset-Validation
    $n = $Org.NewCert
    $script:State.NewCert = [pscustomobject]@{ Subject = $n.Subject; Issuer = $n.Issuer; Thumbprint = $n.Thumbprint; NotAfter = $n.NotAfter }
    $script:State.NewThumb = $n.Thumbprint; $script:State.NewNames = @($n.CertificateDomains); $script:State.PfxPath = $dummyPfx
    $script:State.PfxPassword = ConvertTo-SecureString 'x' -AsPlainText -Force; $script:State.MissingHosts = @(); $script:State.Verified = @{}
    $script:State.Validated = $true
}
$Live = $true
$Calls.Clear()
Invoke-UnattendedRenewal
$iisNow = @('EX01', 'EX02' | ForEach-Object { ($Org.Certs[$_] | Where-Object { -not $_.IsSelfSigned -and $_.Services -match 'IIS' }).Thumbprint })
Assert-That 'renew live: exit code 0' ($script:RenewExitCode -eq 0)
Assert-That 'renew live: new certificate imported and on IIS on both servers' (($iisNow -join ',') -eq 'NEW1,NEW1' -and @($Calls -like 'Import-ExchangeCertificate*').Count -eq 2)
Assert-That 'renew live: hybrid, send and pinned receive connector switched' ($Org.Hybrid -match 'R12' -and $Org.Send[0].TlsCertificateName -match 'R12' -and $Org.Receive['EX01'][0].TlsCertificateName -match 'R12')
Assert-That 'renew live: unpinned frontend connectors left alone' (-not $Org.Receive['EX02'][0].TlsCertificateName -and -not $Org.Receive['EX01'][1].TlsCertificateName)
Assert-That 'renew live: internal transport certificate untouched, old certificate kept' (@($Calls -like 'Set-TransportService*').Count -eq 0 -and @($Calls -like 'Remove-*').Count -eq 0)
$snapB = Get-ChildItem -LiteralPath $tmp -Filter 'Snapshot_*_before-StepB.json' | Sort-Object LastWriteTime | Select-Object -Last 1
Assert-That 'renew live: snapshot saved before Step B' ([bool]$snapB)

# ---------------------------------------------------------------------------------------------
# Rollback from the Step B snapshot
# ---------------------------------------------------------------------------------------------
$plan = @(Get-RollbackPlan -Snapshot (Get-Content -LiteralPath $snapB.FullName -Raw | ConvertFrom-Json))
$kinds = (@($plan | ForEach-Object { "$($_.Kind)" }) | Sort-Object) -join ','
Assert-That 'rollback plan: one row per command' (@($plan | Where-Object { $_ -is [array] }).Count -eq 0)
Assert-That "rollback plan: IIS x2, hybrid, send, receive ($kinds)" ($kinds -eq 'Hybrid,IIS,IIS,Receive,Send')
$Calls.Clear()
Invoke-Rollback -Path $snapB.FullName
$iisNow = @('EX01', 'EX02' | ForEach-Object { ($Org.Certs[$_] | Where-Object { -not $_.IsSelfSigned -and $_.Services -match 'IIS' }).Thumbprint })
Assert-That 'rollback: IIS and connectors back to the old certificate' (($iisNow -join ',') -eq 'OLD1,OLD1' -and $Org.Hybrid -eq $oldTls -and $Org.Send[0].TlsCertificateName -eq $oldTls -and $Org.Receive['EX01'][0].TlsCertificateName -eq $oldTls)
Assert-That 'rollback: nothing left to roll back' (@(Get-RollbackPlan -Snapshot (Get-Content -LiteralPath $snapB.FullName -Raw | ConvertFrom-Json)).Count -eq 0)

# ---------------------------------------------------------------------------------------------
# Renewal with -RemoveOld: removes only the previous IIS certificate
# ---------------------------------------------------------------------------------------------
$RemoveOld = $true
$Calls.Clear()
Invoke-UnattendedRenewal
$left = @('EX01', 'EX02' | ForEach-Object { $Org.Certs[$_] | ForEach-Object { $_.Thumbprint } }) | Select-Object -Unique
Assert-That 'renew -RemoveOld: OLD1 removed on both servers' ($script:RenewExitCode -eq 0 -and $left -notcontains 'OLD1' -and @($Calls -like 'Remove-ExchangeCertificate*').Count -eq 2)
Assert-That 'renew -RemoveOld: unrelated certificate and Auth certificate kept' ($left -contains 'OTHER1' -and $left -contains 'AUTH1')
$RemoveOld = $false; $Live = $false
$Calls.Clear()
Invoke-UnattendedRenewal
Assert-That 'renew: nothing to do when the certificate is fresh' ($script:RenewExitCode -eq 0 -and $Calls.Count -eq 0 -and ((& $logText) -match 'days left - nothing to do'))

# ---------------------------------------------------------------------------------------------
# Dry-run tools: POP/IMAP, rolling restart, CSR, Edge package
# ---------------------------------------------------------------------------------------------
$script:ui.DryRunCheck.IsChecked = $true
$Org.Pop['EX01'] = 'ex01.contoso.local'
$Calls.Clear()
Set-PopImapCertificateName -Server 'EX01'
Assert-That 'POP/IMAP (dry run): name not on the certificate is changed to one that is' (((& $logText) -match '\[DRY RUN\] Set-PopSettings -Server EX01 -X509CertificateName mail\.contoso\.com') -and $Calls.Count -eq 0)
Invoke-RollingRestart
Assert-That 'rolling restart (dry run) logs both servers' (((& $logText) -match '\[DRY RUN\] Invoke-Command -ComputerName ex02\.contoso\.local \{ iisreset /noforce \}') -and $Calls.Count -eq 0)
$script:ui.LeNamesBox.Text = "mail.contoso.com`r`nex01.contoso.local"
New-CertificateRequest
Assert-That 'CSR (dry run) accepts internal names for an internal CA' (((& $logText) -match "\[DRY RUN\] New-ExchangeCertificate -Server EX01 -GenerateRequest -SubjectName 'CN=mail\.contoso\.com' -DomainName mail\.contoso\.com,ex01\.contoso\.local") -and $Calls.Count -eq 0)

New-EdgePackage
$edgeDir = Get-ChildItem -LiteralPath $tmp -Directory -Filter 'EdgePackage_*' | Select-Object -First 1
$edgeScript = Join-Path $edgeDir.FullName 'Install-EdgeCertificate.ps1'
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($edgeScript, [ref]$t, [ref]$e)
$edgeText = Get-Content -LiteralPath $edgeScript -Raw
Assert-That 'Edge package: generated script parses' (-not $e)
Assert-That "Edge package: thumbprint and escaped TLS name (Let''s Encrypt) inserted" ($edgeText -match "\`$thumb = 'NEW1'" -and $edgeText -match "O=Let''s Encrypt" -and (Test-Path (Join-Path $edgeDir.FullName 'certificate.pfx')))

# ---------------------------------------------------------------------------------------------
# Rollback: self-signed IIS certificate and empty POP/IMAP names
# ---------------------------------------------------------------------------------------------
Reset-MockOrg
$script:ui.DryRunCheck.IsChecked = $false
$Org.Certs['EX02'].Remove(($Org.Certs['EX02'] | Where-Object { $_.Thumbprint -eq 'OLD1' }))   # EX02: only its self-signed certificate on IIS
$Org.Pop['EX02'] = ''
Save-ChangeSnapshot -Before 'Test'
$snapT = Get-ChildItem -LiteralPath $tmp -Filter 'Snapshot_*_before-Test.json' | Sort-Object LastWriteTime | Select-Object -Last 1
$snapObj = Get-Content -LiteralPath $snapT.FullName -Raw | ConvertFrom-Json
Assert-That 'snapshot v2: self-signed IIS certificate saved, CA certificate first' ($snapObj.Version -eq 2 -and (@($snapObj.Servers.EX02.Iis) -join ',') -eq 'SELF2' -and @($snapObj.Servers.EX01.Iis)[0] -eq 'OLD1')
# the change: NEW1 takes IIS on EX02, POP/IMAP get a name
($Org.Certs['EX02'] | Where-Object { $_.Thumbprint -eq 'SELF2' }).Services = 'SMTP'
$c = $Org.NewCert.PSObject.Copy(); $c.Services = 'IIS, SMTP'; [void]$Org.Certs['EX02'].Add($c)
$Org.Pop['EX02'] = 'mail.contoso.com'
$plan = @(Get-RollbackPlan -Snapshot $snapObj)
Assert-That 'rollback plan: back to the self-signed IIS certificate on EX02' (@($plan | Where-Object { $_.Kind -eq 'IIS' -and $_.Server -eq 'EX02' -and $_.Value -eq 'SELF2' }).Count -eq 1)
Assert-That 'rollback plan: empty POP and IMAP names restored as $null' (@($plan | Where-Object { $_.Kind -in 'Pop', 'Imap' -and $_.Server -eq 'EX02' -and $null -eq $_.Value -and $_.Text -match 'X509CertificateName \$null$' }).Count -eq 2)
Assert-That 'rollback plan: EX01 unchanged -> no rows for EX01' (@($plan | Where-Object { $_.Server -eq 'EX01' }).Count -eq 0)
$v1 = $snapObj | ConvertTo-Json -Depth 6 | ConvertFrom-Json; $v1.PSObject.Properties.Remove('Version')
Assert-That 'rollback plan: version 1 snapshot ("" = unknown) leaves POP/IMAP alone' (@(Get-RollbackPlan -Snapshot $v1 | Where-Object { $_.Kind -in 'Pop', 'Imap' }).Count -eq 0)
$v1.Servers.EX02.Pop = $null; $snapObj.Servers.EX02.Pop = $null
Assert-That 'rollback plan: POP name that could not be read is not restored' (@(Get-RollbackPlan -Snapshot $snapObj | Where-Object { $_.Kind -eq 'Pop' }).Count -eq 0)
Invoke-Rollback -Path $snapT.FullName
$iis2 = @($Org.Certs['EX02'] | Where-Object { $_.Services -match 'IIS' } | ForEach-Object { $_.Thumbprint })
Assert-That 'rollback live: EX02 IIS back on SELF2, POP/IMAP name cleared' ($iis2 -contains 'SELF2' -and @($Calls -like 'Enable-ExchangeCertificate EX02 SELF2 IIS').Count -eq 1 -and [string]::IsNullOrEmpty($Org.Pop['EX02']))
$script:ui.DryRunCheck.IsChecked = $true

# ---------------------------------------------------------------------------------------------
# CSR completion pairs the certificate with its request by PUBLIC KEY (keys are in memory only)
# ---------------------------------------------------------------------------------------------
Reset-MockOrg
$newReq = { param($k) New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=mail.contoso.com', $k, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) }
$keyA = [System.Security.Cryptography.RSA]::Create(2048); $keyB = [System.Security.Cryptography.RSA]::Create(2048)
$reqA = & $newReq $keyA; $reqB = & $newReq $keyB
$csrA = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`n" + [Convert]::ToBase64String($reqA.CreateSigningRequest(), 'InsertLineBreaks') + "`r`n-----END NEW CERTIFICATE REQUEST-----"
$csrB = [Convert]::ToBase64String($reqB.CreateSigningRequest())
$issuedA = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $reqA.CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddDays(30)).RawData)   # public part only
$placeB = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $reqB.CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddDays(30)).RawData)
$cerPath = Join-Path $tmp 'issued.cer'; [IO.File]::WriteAllBytes($cerPath, $issuedA.RawData)
Assert-That 'CSR public key == issued certificate public key (DER parser)' ((ConvertTo-HexString (Get-CsrSpki $csrA)) -eq (ConvertTo-HexString (Get-CertSpki $issuedA)) -and (ConvertTo-HexString (Get-CsrSpki $csrB)) -ne (ConvertTo-HexString (Get-CertSpki $issuedA)))
function Add-Pending($Server, $Thumb, $Csr, $Raw) {
    $p = [pscustomobject]@{ Thumbprint = $Thumb; Subject = 'CN=mail.contoso.com'; Status = 'PendingRequest'; Services = 'None'; IsSelfSigned = $false; Issuer = 'CN=mail.contoso.com'; NotAfter = (Get-Date).AddDays(30); CertificateDomains = @('mail.contoso.com'); HasPrivateKey = $true; CertificateRequest = $Csr; RawData = $Raw }
    [void]$Org.Certs[$Server].Add($p)
}
# the same name requested on both servers: EX01 has key B (placeholder certificate), EX02 has key A (request text only)
Add-Pending 'EX01' 'PENDB' $null $placeB.RawData
Add-Pending 'EX02' 'PENDA' $csrA $null
$mark = (& $logText).Length; $Calls.Clear()
Complete-CertificateRequest -Path $cerPath
$runLog = (& $logText).Substring($mark)
Assert-That 'CSR complete (dry run): imported only where the key is (EX02), not EX01' ($runLog -match 'Matched by public key: the request on EX02' -and $runLog -match '\[DRY RUN\] Import-ExchangeCertificate -Server EX02' -and $runLog -notmatch 'Import-ExchangeCertificate -Server EX01' -and $Calls.Count -eq 0)
$script:ui.ServerList.SelectedItems.Clear(); [void]$script:ui.ServerList.SelectedItems.Add('EX01')
$e = $null; try { Complete-CertificateRequest -Path $cerPath } catch { $e = $_.Exception.Message }
Assert-That 'CSR complete: request with another public key is refused, nothing imported' ($e -match 'different public key' -and $Calls.Count -eq 0)
$script:ui.ServerList.SelectAll()
Reset-MockOrg
Add-Pending 'EX01' 'PEND1' $null $null; Add-Pending 'EX02' 'PEND2' $null $null   # keys unreadable on both
$e = $null; try { Complete-CertificateRequest -Path $cerPath } catch { $e = $_.Exception.Message }
Assert-That 'CSR complete: two requests with unreadable keys -> asks to select one server' ($e -match 'cannot tell which one' -and $Calls.Count -eq 0)
# live, name-only match on a server without the key: the key-less copy is removed again
Reset-MockOrg
Add-Pending 'EX01' 'PEND1' $null $null
$realImport = ${function:global:Import-ExchangeCertificate}
function global:Import-ExchangeCertificate { [CmdletBinding()] param($Server, $FileData) $Calls.Add("Import-ExchangeCertificate $Server"); [void]$Org.Certs["$Server"].Add([pscustomobject]@{ Thumbprint = $issuedA.Thumbprint; Subject = $issuedA.Subject; Status = 'Valid'; Services = 'None'; HasPrivateKey = $false; IsSelfSigned = $false; NotAfter = $issuedA.NotAfter; CertificateDomains = @() }) }
$script:ui.DryRunCheck.IsChecked = $false
$e = $null; try { Complete-CertificateRequest -Path $cerPath } catch { $e = $_.Exception.Message }
Assert-That 'CSR complete live: copy without private key removed, error raised' ($e -match 'could not be paired' -and @($Calls -like "Remove-ExchangeCertificate EX01 $($issuedA.Thumbprint)").Count -eq 1 -and -not ($Org.Certs['EX01'] | Where-Object { $_.Thumbprint -eq $issuedA.Thumbprint }))
Set-Item -Path function:global:Import-ExchangeCertificate -Value $realImport
$script:ui.DryRunCheck.IsChecked = $true
$keyA.Dispose(); $keyB.Dispose()
Reset-MockOrg

# ---------------------------------------------------------------------------------------------
# HAProxy package: generated script, then run for real with bash + openssl against a throwaway PFX
# ---------------------------------------------------------------------------------------------
New-HaproxyPackage
$hpDir = Get-ChildItem -LiteralPath $tmp -Directory -Filter 'HaproxyPackage_*' | Select-Object -First 1
$hpScript = Join-Path $hpDir.FullName 'install-haproxy-cert.sh'
$hpText = [IO.File]::ReadAllText($hpScript)
Assert-That 'HAProxy package: PFX + script, LF only, thumbprint and target filled in' ((Test-Path (Join-Path $hpDir.FullName 'certificate.pfx')) -and $hpText -notmatch "`r" -and $hpText -match "THUMB='NEW1'" -and $hpText -match '/etc/haproxy/certs/mail\.contoso\.com\.pem' -and $hpText -notmatch '__[A-Z]+__')
$bash = @("$env:ProgramFiles\Git\bin\bash.exe", "$env:ProgramFiles\Git\usr\bin\bash.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $bash) { Write-Host 'SKIP HAProxy script run: Git bash not found' -ForegroundColor Yellow }
else {
    $hp = ($hpDir.FullName -replace '\\', '/')
    $runSh = Join-Path $tmp 'hp-run.sh'
    $runText = @'
exec 2>&1
set -u
D="$1"; cd "$D"
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -subj /CN=mail.contoso.com -days 2 >/dev/null 2>&1
openssl pkcs12 -export -inkey k.pem -in c.pem -out certificate.pfx -passout pass:t3st >/dev/null 2>&1
rm -f k.pem
FP="$(openssl x509 -in c.pem -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
# Windows test host only: Git bash maps %TEMP% to /tmp, which Git's native openssl.exe cannot open - use C:/ paths
mkdir -p w; export TMPDIR="$D/w"
sed -e "s/^THUMB=.*/THUMB='$FP'/" -e "s#^DIR=.*#DIR='$D'#" install-haproxy-cert.sh > run.sh
mkdir -p bin certs bak; printf '#!/bin/sh\nexit ${FAKE_HAPROXY_RC:-0}\n' > bin/haproxy; printf '#!/bin/sh\necho reloaded >> "%s/reload.log"\n' "$D" > bin/systemctl; chmod +x bin/*
echo "    bind :443 ssl crt $D/certs/" > haproxy.cfg
export PATH="$(cd "$D/bin" && pwd):$PATH" HAPROXY_CFG="$D/haproxy.cfg" BACKUP_DIR="$D/bak" PFXPASS=t3st
T="$D/certs/mail.pem"
bash run.sh --check "$T" >/dev/null 2>&1; echo "check=$? installed=$([ -f "$T" ] && echo y || echo n)"
echo old > "$T"
bash run.sh "$T" >/dev/null 2>&1; echo "install=$? reload=$(cat reload.log 2>/dev/null | wc -l | tr -d ' ') key=$(grep -c 'PRIVATE KEY-----' "$T") certfp=$(openssl x509 -in "$T" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':') backups=$(ls bak | wc -l | tr -d ' ') incerts=$(ls certs | wc -l | tr -d ' ')"
echo "expect=$FP"
cp "$T" good.pem; echo older > "$T"
FAKE_HAPROXY_RC=1 bash run.sh "$T" >/dev/null 2>&1; echo "badcfg=$? restored=$(cat "$T")"
sed -i "s/^THUMB=.*/THUMB='0000'/" run.sh; bash run.sh --check "$T" >/dev/null 2>&1; echo "wrongthumb=$?"
sed -i "s/^THUMB=.*/THUMB='$FP'/" run.sh; cp good.pem "$T"; M="$(PATH=/usr/bin:/bin bash run.sh "$T" 2>&1)"; echo "nohaproxy=$? untouched=$(cmp -s good.pem "$T" && echo y || echo n) early=$(echo "$M" | grep -q 'Nothing was changed' && echo y || echo n) backups=$(ls bak | wc -l | tr -d ' ')"
rm -rf certificate.pfx good.pem "$T" bak w
'@
    [IO.File]::WriteAllText($runSh, ($runText -replace "`r`n", "`n"))
    $o = (& $bash $runSh.Replace('\', '/') $hp 2>&1 | Out-String)
    Write-Host $o.Trim()
    $exp = if ($o -match 'expect=([0-9A-F]+)') { $Matches[1] } else { 'none' }
    Assert-That 'HAProxy script --check: converts and verifies, installs nothing' ($o -match 'check=0 installed=n')
    Assert-That 'HAProxy script: installs PEM with key + right certificate, backup outside certs, reload' ($o -match "install=0 reload=1 key=2 certfp=$exp backups=1 incerts=1")
    Assert-That 'HAProxy script: haproxy -c failure restores the previous file' ($o -match 'badcfg=1 restored=older')
    Assert-That 'HAProxy script: wrong PFX (thumbprint) refused' ($o -match 'wrongthumb=1')
    Assert-That 'HAProxy script: haproxy not installed -> stops before touching the file' ($o -match 'nohaproxy=1 untouched=y early=y backups=2')
}

# ---------------------------------------------------------------------------------------------
# Step D: Exchange Online connectors (name-only checks) - mocked Exchange Online cmdlets with prefix "Cloud"
# ---------------------------------------------------------------------------------------------
$wild = @('*.contoso.com', 'contoso.com')
Assert-That 'EXO names: exact name / wildcard value / host under wildcard certificate' (
    (Test-ExoNameCovered 'mail.contoso.com' @('mail.contoso.com') Inbound) -and (Test-ExoNameCovered '*.contoso.com' @('mail.contoso.com') Inbound) -and
    -not (Test-ExoNameCovered 'mail.contoso.com' $wild Inbound) -and (Test-ExoNameCovered 'mail.contoso.com' $wild Outbound) -and
    -not (Test-ExoNameCovered 'a.b.contoso.com' $wild Outbound) -and -not (Test-ExoNameCovered 'mail.fabrikam.com' @('mail.contoso.com') Outbound))
$inb = @(
    [pscustomobject]@{ Identity = 'Inbound from 1111'; ConnectorType = 'OnPremises'; ConnectorSource = 'HybridWizard'; TlsSenderCertificateName = 'mail.contoso.com' }
    [pscustomobject]@{ Identity = 'Gateway'; ConnectorType = 'OnPremises'; ConnectorSource = 'Default'; TlsSenderCertificateName = 'relay.fabrikam.net' }
    [pscustomobject]@{ Identity = 'IP only'; ConnectorType = 'OnPremises'; ConnectorSource = 'Default'; TlsSenderCertificateName = $null }
    [pscustomobject]@{ Identity = 'Partner'; ConnectorType = 'Partner'; ConnectorSource = 'Default'; TlsSenderCertificateName = 'partner.example' })
$outb = @(
    [pscustomobject]@{ Identity = 'Outbound to 1111'; ConnectorType = 'OnPremises'; ConnectorSource = 'HybridWizard'; TlsSettings = 'DomainValidation'; TlsDomain = 'mail.contoso.com' }
    [pscustomobject]@{ Identity = 'No validation'; ConnectorType = 'OnPremises'; ConnectorSource = 'Default'; TlsSettings = 'EncryptionOnly'; TlsDomain = $null })
$same = @(Get-ExoConnectorPlan -Inbound $inb -Outbound $outb -Names @('mail.contoso.com', 'autodiscover.contoso.com') -Subject 'CN=mail.contoso.com' -OwnNames @('mail.contoso.com'))
Assert-That 'EXO plan, same names (normal renewal): nothing to update' (@($same | Where-Object Action -eq 'UPDATE').Count -eq 0 -and $same.Count -eq 5)
$chg = @(Get-ExoConnectorPlan -Inbound $inb -Outbound $outb -Names $wild -Subject 'CN=*.contoso.com' -OwnNames @('mail.contoso.com'))
$upd = @($chg | Where-Object Action -eq 'UPDATE')
Assert-That 'EXO plan, mail.* -> wildcard: inbound updated to *.contoso.com, outbound host still covered' ($upd.Count -eq 1 -and $upd[0].Connector -eq 'Inbound from 1111' -and $upd[0].New -eq '*.contoso.com' -and ($chg | Where-Object Connector -eq 'Outbound to 1111').Action -eq 'OK')
Assert-That 'EXO plan: foreign gateway, IP-only and non-validating connectors left alone' ((@($chg | Where-Object { $_.Connector -in 'Gateway', 'IP only', 'No validation' -and $_.Action -eq 'SKIP' })).Count -eq 3)
$chg2 = @(Get-ExoConnectorPlan -Inbound $inb -Outbound $outb -Names @('smtp.contoso.com') -Subject 'CN=smtp.contoso.com' -OwnNames @('mail.contoso.com'))
Assert-That 'EXO plan, renamed host: inbound and outbound set to the new CN' ((@($chg2 | Where-Object { $_.Action -eq 'UPDATE' -and $_.New -eq 'smtp.contoso.com' })).Count -eq 2)

# Step D end to end against mocked Exchange Online
$global:Cloud = @{ In = @($inb | ForEach-Object { $_.PSObject.Copy() }); Out = @($outb | ForEach-Object { $_.PSObject.Copy() }) }
function global:Get-CloudInboundConnector { [CmdletBinding()] param($Identity) if ($Identity) { $Cloud.In | Where-Object Identity -eq $Identity } else { $Cloud.In } }
function global:Get-CloudOutboundConnector { [CmdletBinding()] param($Identity) if ($Identity) { $Cloud.Out | Where-Object Identity -eq $Identity } else { $Cloud.Out } }
function global:Set-CloudInboundConnector { [CmdletBinding()] param($Identity, $TlsSenderCertificateName) $Calls.Add("EXO Set-InboundConnector $Identity"); ($Cloud.In | Where-Object Identity -eq $Identity).TlsSenderCertificateName = $TlsSenderCertificateName }
function global:Set-CloudOutboundConnector { [CmdletBinding()] param($Identity, $TlsDomain) $Calls.Add("EXO Set-OutboundConnector $Identity"); ($Cloud.Out | Where-Object Identity -eq $Identity).TlsDomain = $TlsDomain }
Reset-MockOrg
Update-Inventory
Invoke-ValidatePfx
$script:State.NewNames = $wild; $script:State.NewCert.Subject = 'CN=*.contoso.com'
$script:ui.DryRunCheck.IsChecked = $true; $Calls.Clear(); $mark = (& $logText).Length
Invoke-UpdateExoConnectors
$runLog = (& $logText).Substring($mark)
Assert-That 'Step D (dry run): logs Set-InboundConnector, changes nothing' ($runLog -match "\[DRY RUN\] Set-InboundConnector -Identity 'Inbound from 1111' -TlsSenderCertificateName '\*\.contoso\.com'" -and $Calls.Count -eq 0 -and $Cloud.In[0].TlsSenderCertificateName -eq 'mail.contoso.com')
$script:ui.DryRunCheck.IsChecked = $false; $Calls.Clear()
Invoke-UpdateExoConnectors
$snapD = Get-ChildItem -LiteralPath $tmp -Filter 'Snapshot_*_before-StepD.json' | Sort-Object LastWriteTime | Select-Object -Last 1
Assert-That 'Step D live: only the hybrid inbound connector changed, snapshot saved' ($Cloud.In[0].TlsSenderCertificateName -eq '*.contoso.com' -and $Cloud.In[1].TlsSenderCertificateName -eq 'relay.fabrikam.net' -and @($Calls).Count -eq 1 -and [bool]$snapD)
$planD = @(Get-RollbackPlan -Snapshot (Get-Content -LiteralPath $snapD.FullName -Raw | ConvertFrom-Json))
Assert-That 'Step D rollback plan: one Exchange Online row' ($planD.Count -eq 1 -and $planD[0].Kind -eq 'ExoInbound' -and $planD[0].Value -eq 'mail.contoso.com')
Invoke-Rollback -Path $snapD.FullName
Assert-That 'Step D rollback: Exchange Online inbound connector restored' ($Cloud.In[0].TlsSenderCertificateName -eq 'mail.contoso.com')
$keepTest = ${function:Test-ExoConnected}; function Test-ExoConnected { $false }
$mark = (& $logText).Length
$planNo = @(Get-RollbackPlan -Snapshot (Get-Content -LiteralPath $snapD.FullName -Raw | ConvertFrom-Json))
Assert-That 'Step D rollback without an Exchange Online session: warns to sign in, no cloud rows' ((& $logText).Substring($mark) -match 'click "Check Exchange Online connectors"' -and @($planNo | Where-Object { $_.Kind -like 'Exo*' }).Count -eq 0)
Set-Item -Path function:Test-ExoConnected -Value $keepTest
$script:ui.DryRunCheck.IsChecked = $true

# ---------------------------------------------------------------------------------------------
# Auth certificate -> Entra ID: public .cer export, Microsoft-signature gate, separate console window
# ---------------------------------------------------------------------------------------------
Reset-MockOrg
$authKey = [System.Security.Cryptography.RSA]::Create(2048)
$authReq = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=Microsoft Exchange Server Auth Certificate', $authKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$authPub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $authReq.CreateSelfSigned([DateTimeOffset]::Now, [DateTimeOffset]::Now.AddYears(5)).RawData)
$authKey.Dispose()
foreach ($sv in 'EX01', 'EX02') { $a = $Org.Certs[$sv] | Where-Object Thumbprint -eq 'AUTH1'; $a | Add-Member -NotePropertyName RawData -NotePropertyValue $authPub.RawData -Force }
function global:Get-AuthServer { [CmdletBinding()] param() [pscustomobject]@{ Name = 'EvoSts - 1234'; ApplicationIdentifier = 'aaaa-bbbb' } }
$script:HybridAppScriptPath = Join-Path $tmp 'hybridapp\ConfigureExchangeHybridApplication.ps1'
$global:SigStatus = 'Valid'
function Get-AuthenticodeSignature { param($LiteralPath) [pscustomobject]@{ Status = $global:SigStatus; SignerCertificate = [pscustomobject]@{ Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' } } }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec) $Calls.Add("download $Uri"); Set-Content -LiteralPath $OutFile -Value '# fake' }
$global:Started = New-Object System.Collections.Generic.List[object]
function Start-Process { param($FilePath, $ArgumentList) $Started.Add(@{ File = $FilePath; Args = $ArgumentList }) }
$script:ui.DryRunCheck.IsChecked = $true; $Calls.Clear(); $mark = (& $logText).Length
Invoke-UploadAuthToEntra
$runLog = (& $logText).Substring($mark)
Assert-That 'Auth upload (dry run): commands logged, nothing exported, downloaded or started' ($runLog -match '\[DRY RUN\] \(new PowerShell window\) .*-UpdateCertificate -CertificateMethod File -CertificateInformation .*auth-current-AUTH1\.cer' -and $Calls.Count -eq 0 -and $Started.Count -eq 0 -and -not (Get-ChildItem -LiteralPath $tmp -Directory -Filter 'AuthCertUpload_*'))
$script:ui.DryRunCheck.IsChecked = $false
Invoke-UploadAuthToEntra
$upDir = Get-ChildItem -LiteralPath $tmp -Directory -Filter 'AuthCertUpload_*' | Select-Object -First 1
$cer = @(Get-ChildItem -LiteralPath $upDir.FullName -Filter '*.cer')
$cmd = if ($Started.Count) { [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(@($Started[0].Args)[-1])) } else { '' }
Assert-That 'Auth upload: public certificate exported (no private key)' ($cer.Count -eq 1 -and (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [IO.File]::ReadAllBytes($cer[0].FullName))).Thumbprint -eq $authPub.Thumbprint -and -not (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [IO.File]::ReadAllBytes($cer[0].FullName))).HasPrivateKey)
Assert-That 'Auth upload: signed script downloaded and started in a new window (File mode)' ($Started.Count -eq 1 -and @($Started[0].Args) -contains '-NoExit' -and $cmd -match [regex]::Escape($script:HybridAppScriptPath) -and $cmd -match '-UpdateCertificate -CertificateMethod File -CertificateInformation' -and $cmd -match [regex]::Escape($cer[0].FullName))
$global:SigStatus = 'HashMismatch'; $Started.Clear(); Remove-Item -LiteralPath $script:HybridAppScriptPath -Force
$e = $null; try { Invoke-UploadAuthToEntra } catch { $e = $_.Exception.Message }
Assert-That 'Auth upload: script without a valid Microsoft signature is deleted and not run' ($e -match 'does not have a valid Microsoft signature' -and $Started.Count -eq 0 -and -not (Test-Path -LiteralPath $script:HybridAppScriptPath))
$global:SigStatus = 'Valid'
function global:Get-AuthConfig { [pscustomobject]@{ CurrentCertificateThumbprint = 'AUTH1'; PreviousCertificateThumbprint = $null; NextCertificateThumbprint = 'AUTH2'; NextCertificateEffectiveDate = (Get-Date).AddDays(2) } }
$e = $null; try { Invoke-UploadAuthToEntra } catch { $e = $_.Exception.Message }
Assert-That 'Auth upload: next Auth certificate missing on the servers -> stops, nothing started' ($e -match 'next Auth certificate AUTH2 was not found' -and $Started.Count -eq 0)
function global:Get-AuthConfig { [pscustomobject]@{ CurrentCertificateThumbprint = $Org.Auth; PreviousCertificateThumbprint = $null; NextCertificateThumbprint = $null; NextCertificateEffectiveDate = $null } }
Remove-Item function:Start-Process, function:Invoke-WebRequest, function:Get-AuthenticodeSignature
$script:ui.DryRunCheck.IsChecked = $true
Reset-MockOrg

# ---------------------------------------------------------------------------------------------
# -ForceRenew never "renews" to the certificate that is already on IIS
# ---------------------------------------------------------------------------------------------
$order = Join-Path $env:POSHACME_HOME 'acme-v02.api.letsencrypt.org\1\mail.contoso.com'
New-Item -ItemType Directory -Path $order -Force | Out-Null
[IO.File]::WriteAllBytes((Join-Path $order 'fullchain.pfx'), [byte[]](1..64))
[IO.File]::WriteAllBytes((Join-Path $order 'cert.cer'), $leafCert.RawData)   # public certificate only
@{ MainDomain = 'mail.contoso.com'; PfxPassB64U = 'eA'; CertExpires = (Get-Date).AddDays(80).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $order 'order.json')
$saved = @(& $script:RealFindAcme)
Assert-That 'saved ACME certificate: thumbprint read from cert.cer' ($saved.Count -eq 1 -and $saved[0].Thumbprint -eq $leafCert.Thumbprint)

$iisThumb = "$(($Org.Certs['EX01'] | Where-Object { -not $_.IsSelfSigned -and $_.Services -match 'IIS' } | Select-Object -First 1).Thumbprint)"
$Live = $false; $RemoveOld = $false; $ForceRenew = $true
function Find-AcmeSavedCertificates { [pscustomobject]@{ Path = $dummyPfx; Password = '***'; MainDomain = 'mail.contoso.com'; Expires = (Get-Date).AddDays(80); Written = (Get-Date); Server = 'acme-v02.api.letsencrypt.org'; Thumbprint = $iisThumb } }
$mark = (& $logText).Length; $Calls.Clear()
Invoke-UnattendedRenewal
$runLog = (& $logText).Substring($mark)
Assert-That "-ForceRenew: certificate already on IIS ($iisThumb) is not reused, a new one is requested" ($runLog -notmatch 'Reusing the certificate' -and $runLog -match 'Dry run: stopped after the ACME step' -and $Calls.Count -eq 0)

function Find-AcmeSavedCertificates { [pscustomobject]@{ Path = $dummyPfx; Password = '***'; MainDomain = 'mail.contoso.com'; Expires = (Get-Date).AddDays(80); Written = (Get-Date); Server = 'acme-v02.api.letsencrypt.org'; Thumbprint = $null } }
$mark = (& $logText).Length
Invoke-UnattendedRenewal
$runLog = (& $logText).Substring($mark)
Assert-That '-ForceRenew: saved certificate with unknown thumbprint is not reused' ($runLog -notmatch 'Reusing the certificate' -and $runLog -match 'Dry run: stopped after the ACME step')

# Validation says the reused PFX is the IIS certificate (e.g. cert.cer missing): rejected after validation too
function Find-AcmeSavedCertificates { [pscustomobject]@{ Path = $dummyPfx; Password = '***'; MainDomain = 'mail.contoso.com'; Expires = (Get-Date).AddDays(80); Written = (Get-Date); Server = 'acme-v02.api.letsencrypt.org'; Thumbprint = 'SOMETHINGELSE' } }
$Org.NewCert.Thumbprint = $iisThumb
$mark = (& $logText).Length
Invoke-UnattendedRenewal
$runLog = (& $logText).Substring($mark)
Assert-That '-ForceRenew: reused PFX that validates as the IIS certificate is dropped' ($runLog -match 'is the one already on IIS - not reused' -and $runLog -match 'Dry run: stopped after the ACME step')
$ForceRenew = $false

# ---------------------------------------------------------------------------------------------
# POP/IMAP: no restart when nothing changed
# ---------------------------------------------------------------------------------------------
$script:ui.DryRunCheck.IsChecked = $true
$Org.Pop['EX01'] = 'mail.contoso.com'
$script:State.NewNames = @('mail.contoso.com', 'autodiscover.contoso.com')
$mark = (& $logText).Length
Set-PopImapCertificateName -Server 'EX01' -ServicesChanged $false
$runLog = (& $logText).Substring($mark)
Assert-That 'POP/IMAP: names already on the certificate and services unchanged -> no restart' ($runLog -notmatch 'Restart the running POP3/IMAP4' -and $runLog -match 'services not restarted')
$mark = (& $logText).Length
Set-PopImapCertificateName -Server 'EX01' -ServicesChanged $true
Assert-That 'POP/IMAP: restart when the certificate was just enabled for POP/IMAP' ((& $logText).Substring($mark) -match '\[DRY RUN\] Restart the running POP3/IMAP4')

# ---------------------------------------------------------------------------------------------
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($script:Failures) { Write-Host "`n$($script:Failures) check(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host "`nAll checks passed." -ForegroundColor Green
exit 0
