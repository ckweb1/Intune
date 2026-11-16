# Cloud PKI leaf certificate revocation

Version: **1.1.0**

Revoke all active leaf certificates in the collected inventory of one Microsoft Intune Cloud PKI issuing CA. This standalone administration tool is **not** an Intune Detect/Remediate package.

## Safety and support boundary

- The script never pauses, disables, deletes or revokes the issuing CA.
- Leaf revocation is irreversible. There is no rollback or un-revoke operation; recovery requires issuing and deploying replacement certificates.
- The CA can continue issuing certificates. Certificates issued after inventory collection are not included.
- Client revocation checking, CRL publication and cached revocation information affect when revocation is enforced.
- This community tool is provided AS IS, without warranties. It is not a Microsoft support statement or supported Microsoft product. Review and test in a non-production tenant before any production use.
- Publication of this code does not establish a license grant. Follow the repository's applicable licensing terms and obtain any required redistribution permission.

## Prerequisites and execution context

- Interactive Windows PowerShell 5.1 with .NET Framework 4.7.2 or later, or PowerShell 7.
- Microsoft.Graph.Authentication **2.4.0 or later**. This is a technical minimum for the parameters used, not a recommendation to install that old version.
- Delegated Graph authentication in the Global cloud, an active Intune/Cloud PKI entitlement, and an Intune role authorized to revoke leaf certificates.
- Admin consent for `DeviceManagementCloudCA.ReadWrite.All` and `DeviceManagementConfiguration.Read.All`.
- Existing writable parent directories for CSV and CMTrace output.

Graph beta action permission documentation is not fully consistent with CA read documentation. Validate authorization against the target tenant before a production run; the script does not grant consent or permissions.

Local administrator rights are not required. If no suitable Graph authentication module is installed, the script offers to install the latest stable PSGallery version for **CurrentUser**, after explicit consent. PowerShellGet, its normal prerequisites and PSGallery access are required for installation. No UAC, execution-policy bypass, repository trust changes or silent prerequisite installation are performed. An already loaded older Graph assembly requires a fresh PowerShell process.

## Preview first

```powershell
.\Revoke-CloudPkiLeafCertificates.ps1 -WhatIf
```

The script reuses a suitable delegated Graph context or signs in, obtains and displays the tenant ID, then offers issuing CAs through `Out-GridView`. Without that command, it uses a numbered console list. Selection is explicit even when only one CA is available; cancellation never selects a default.

For a guest account, supply the intended customer tenant explicitly. Enter environment-specific IDs only at runtime:

```powershell
$tenantId = Read-Host 'Enter the intended tenant GUID'
.\Revoke-CloudPkiLeafCertificates.ps1 -TenantId $tenantId -UseConsoleSelection -WhatIf
```

To supply both IDs instead of selecting the CA:

```powershell
$caId = Read-Host 'Enter the issuing CA GUID'
.\Revoke-CloudPkiLeafCertificates.ps1 -TenantId $tenantId -CaId $caId -WhatIf
```

Only after reviewing the preview, rerun without `-WhatIf`. Normal high-impact confirmation prompts remain enabled. Do not disable confirmations without an independently reviewed operational plan.

## Reports, logging and privacy

Default CSV names start with `CloudPKI-Leaf-Revoke-` and contain a timestamp. The CMTrace log uses the same path with `.log`; `-ReportPath` and `-LogPath` can override them.

- New files only: existing logs and reports are never overwritten.
- Logs use UTC timestamps and CMTrace severity 1 (information), 2 (warning), or 3 (error).
- Script/module versions, setup, selection, inventory, individual results and summary are recorded.
- `-WhatIf` still authenticates, reads Graph and writes local CSV/log files, but does not install modules or send revocation requests.
- Log creation/write failures stop processing. After a successful request, revoked status is checked before a certificate is reported as revoked.
- Individual failures or unverified requests are recorded; a terminating error follows processing of the remaining certificates. Inspect both outputs after any failure.

The source contains no embedded customer names, tenant IDs, CA IDs, credentials or user-specific paths. **Runtime outputs are not anonymized.** They can contain tenant/CA/certificate identifiers, subjects, UPNs, device names, file paths and error details. Do not publish logs, CSV reports, certificates, authentication material or unredacted screenshots. Ignore rules are only a safeguard: explicitly exclude custom output paths before committing.

## Offline validation

Keep the script and [offline harness](Test-RevokeCloudPkiLeafCertificates.ps1) together:

```powershell
.\Test-RevokeCloudPkiLeafCertificates.ps1
```

The 38 focused cases mock Graph, module operations, selection UI, prompts and sleeps. All IDs and names are synthetic fixtures. Tests create and remove their own temporary reports/logs; they do not install modules, elevate, open dialogs or contact a tenant.

Validation passed under Windows PowerShell 5.1 and PowerShell 7. CMTrace record framing is checked automatically, not through the CMTrace UI. Module installation, tenant authorization, live revocation and UI interaction still require separate environment-specific validation.

## Changelog

- **1.1.0**: CMTrace logging, startup/error coverage and log-write safety.
- **1.0.0**: First versioned release; tenant/CA selection, dependency checks, leaf-only revocation, CSV reporting and verification.
