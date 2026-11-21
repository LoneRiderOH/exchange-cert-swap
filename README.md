# Exchange Certificate Swap

A single-file PowerShell **WPF GUI** for replacing the public IIS/SMTP certificate on on-premises **Exchange Server 2016, 2019 and Subscription Edition** mailbox servers using a PFX file. It covers the whole process: inventory, validation, import, enable, verification and safe removal of the old certificate. **Dry run** is on by default.

![Screenshot](docs/screenshot.png)

## Features

- **Inventory**: lists every Exchange certificate on all selected mailbox servers and marks the **Auth (OAuth)** and **internal transport** certificates.
- **Validation before changes (read-only)**:
  - the PFX contains a private key, is in its validity period and has the Server Authentication EKU
  - the chain builds to a trusted root
  - every `InternalUrl`/`ExternalUrl` on the OWA, ECP, EWS, OAB, ActiveSync and MAPI virtual directories, plus the Autodiscover SCP, is covered by the certificate's SANs (wildcards are handled correctly)
  - lists Send and Receive connectors whose `TlsCertificateName` still points to the old certificate, with the `Set-*Connector` command to fix each one
- **Import to multiple servers**: imports the **same PFX** on every selected server with `Import-ExchangeCertificate -FileData`, so the tool doesn't need to be run on each server.
- **Enable for IIS and SMTP**: if `Enable-ExchangeCertificate -Force` replaces the **internal transport certificate**, the tool restores the previous one unless you choose otherwise.
- **Verification on the network**: opens a real TLS connection to each server on port 443 and compares the served thumbprint with the new certificate. It also checks SMTP port 25 with STARTTLS (for information only) and any extra endpoints you list, such as a load balancer or public name.
- **Safe removal of the old certificate**: a certificate is removed only if:
  - its server passed verification
  - it is not the Auth or internal transport certificate
  - it is no longer bound to IIS
  - no connector points to it

  You confirm each removal.
- **Dry run by default**: every command is logged instead of being run. You turn Dry run off on purpose, and the header switches to red **LIVE MODE**.
- **Full log**: each run writes `logs\CertSwap_<timestamp>.log` next to the script. PFX passwords are never logged.
- **No private key is written to the machine that runs the tool**: the PFX is opened with `EphemeralKeySet`, so its key stays in memory. It never goes into a Windows key store or onto a smart card or hardware token. The key is installed only on the Exchange servers, through `Import-ExchangeCertificate`.

## Requirements

| | |
|---|---|
| Exchange | 2016, 2019 or Subscription Edition, **Mailbox** role |
| Where to run | Any Exchange mailbox server, **or** a machine with the Exchange Management Tools installed |
| PowerShell | **Windows PowerShell 5.1** (`powershell.exe`, not PowerShell 7), run as administrator |
| .NET Framework | 4.7.2 or newer |
| Permissions | Organization Management (or a role that can manage Exchange certificates, connectors and transport services) |
| Network | From the machine running the tool to each server's FQDN on TCP 443 (and 25 for the SMTP check) |
| Certificate | A PFX (`.pfx`/`.p12`) **with private key**, ideally including the intermediate CA certificates |

**Not supported:** Edge Transport servers (they aren't in Active Directory; import their certificate locally and recreate the Edge subscription), and Exchange 2013 or older.

## Quick start

1. Download `ExchangeCertTool.ps1` and copy it to an Exchange server.
2. If Windows blocked the download, unblock the file: `Unblock-File .\ExchangeCertTool.ps1`
3. Open **Windows PowerShell as administrator** and run:

   ```powershell
   powershell.exe -STA -ExecutionPolicy Bypass -File .\ExchangeCertTool.ps1
   ```

   The tool loads the Exchange Management Shell by itself. You can also start it from an existing EMS window.

## Step-by-step

> Keep **Dry run** ticked for your first pass and read the log. Then untick it and repeat the steps that change things (3 and 5).

| Tab | What happens | Changes anything? |
|---|---|---|
| **1. Servers & inventory** | Select the mailbox servers to work on (all are selected by default). Review the current certificates. | No |
| **2. New certificate (PFX)** | Browse to the PFX, enter its password and click **Validate**. Read the report. Missing host names and connectors that point to the old certificate appear as warnings. | No |
| **3. Import & enable** | **Step A**: import the PFX on all selected servers. **Step B**: enable it for IIS and SMTP. The old certificate stays on the servers. | Yes |
| **4. Verify** | Checks that Exchange has the new certificate enabled for IIS and SMTP and that it is served on port 443. You can add extra endpoints, such as `mail.contoso.com` or a load balancer address, to check too. | No |
| **5. Remove old certificate** *(optional)* | Click **Load candidates**. The `Blockers` column shows why a certificate can't be removed yet. Select the rows to remove and confirm. | Yes |

After step 3, update any connectors reported on tab 2 with the command the tool shows. Then load the candidates on tab 5 again.

## Things to know

- **Port 443 still serves the old certificate after enabling.** Check the HTTPS binding on *Default Web Site* in IIS Manager. If the binding is correct, run `iisreset /noforce` during a quiet period.
- **Port 25 still shows the old or self-signed certificate.** This is often expected. Exchange chooses the SMTP certificate by matching the receive connector's FQDN, so a connector using the server's own internal name keeps the self-signed certificate. Internet SMTP uses the name on your public MX connector.
- **Internal names such as `.local`**: public CAs can't issue certificates for them. Change the `InternalUrl` values to a public name that is on the certificate, and use split DNS. The tool lists these names during validation.
- **Load balancers or reverse proxies that terminate TLS** (HAProxy, F5, KEMP, NGINX and so on) need the new certificate installed on them separately. Add their address on tab 4 to check it.
- **Hybrid deployments**: if your *Outbound to Office 365* connector or the receive connectors point to the old certificate, update them before removing it, and rerun the Hybrid Configuration Wizard if your process requires it.
- The **Exchange Back End** site (port 444) and the **Auth certificate** are never changed by this tool.

## Testing without Exchange

Dot-source the script with `-LoadOnly`. This defines the functions and builds the window without connecting to Exchange or showing it, so you can supply mock Exchange cmdlets:

```powershell
. .\ExchangeCertTool.ps1 -LoadOnly -LogDirectory $env:TEMP\certtool
```

> ⚠️ Don't create test certificates with `New-SelfSignedCertificate` or `Import-PfxCertificate` on a workstation that has a smart card or USB token middleware installed (e.g. SafeNet Authentication Client). The private key can end up on the token. Use a lab VM for tests.

## Parameters

| Parameter | Description |
|---|---|
| `-LogDirectory <path>` | Folder for log files. Default: `.\logs` next to the script |
| `-LoadOnly` | Load the functions and build the window without connecting to Exchange or showing it (for testing) |

## Disclaimer

The tool changes production Exchange configuration. Test in a lab first, use Dry run, keep the old certificate and PFX until you have verified the change, and run it in a maintenance window. Provided as-is under the MIT License, without warranty.

## License

[MIT](LICENSE)
