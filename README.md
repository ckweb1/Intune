# Intune
unsorted intune apps/ Scripts

## Cloud PKI

- [Cloud PKI leaf certificate revocation](CloudPKI-Leaf-Certificates.md) - revoke active leaf certificates of one selected issuing CA without changing the CA.
- [PowerShell script](Revoke-CloudPkiLeafCertificates.ps1)
- [Synthetic offline tests](Test-RevokeCloudPkiLeafCertificates.ps1)

Start with `-WhatIf`. Revocation is irreversible. Never commit generated logs, CSV reports, credentials, certificates or customer-specific data.
