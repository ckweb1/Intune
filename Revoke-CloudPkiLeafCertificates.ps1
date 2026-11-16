#Requires -Version 5.1
<#
.SYNOPSIS
Revoke all active leaf certificates of one Microsoft Intune Cloud PKI issuing CA.
.DESCRIPTION
Never pauses, disables, revokes or deletes the CA. Only leaf certificates that
are active in the collected inventory are revoked. Certificates issued after
the inventory is collected are not included.

-WhatIf performs authentication and read requests, but no Graph POST requests.
A new CSV report is always written, including with -WhatIf. Existing files are
never overwritten. Each result is flushed immediately.
A CMTrace-compatible log is created before module checks and authentication,
including with -WhatIf. It records progress, warnings and errors with UTC times.
Failure to create or write the log stops processing; existing logs are not
overwritten. Treat logs and CSV reports as customer operational data.

Each successful revocation request is followed by status checks. A failure or
an unverified revocation produces a report entry and a terminating error after
the remaining certificates have been processed. Revocation is irreversible.
CRL publication, client caches and revocation checking affect enforcement.

Without IDs, use the current delegated Graph tenant or sign in, then select
exactly one issuing CA. The tenant ID is displayed before CA selection.
Out-GridView is used when available; otherwise a numbered console list is used.
Cancellation never selects a default CA and causes no Graph changes.

Checks Microsoft.Graph.Authentication before connecting. If no installed version
meets the minimum, offers to install the latest stable PSGallery version for
CurrentUser only. No UAC, elevation, repository trust changes or execution-policy
changes are performed. Declining stops the script. WhatIf never installs modules.
Already loaded older assemblies require a fresh PowerShell process.
.PARAMETER TenantId
Optional customer tenant ID, verified after connecting. Without it, reuse the
current Global delegated tenant or obtain the tenant ID after interactive login.
For a guest account targeting a customer tenant, supply that tenant ID explicitly.
This script does not enumerate all tenants accessible to an account.
.PARAMETER CaId
Optional issuing CA object ID in Intune, not its certificate thumbprint.
Without it, show active or paused issuing CAs for explicit single selection.
.PARAMETER UseConsoleSelection
Use a numbered console list instead of Out-GridView, including on headless hosts.
.PARAMETER ReportPath
Path for a new CSV file. Its parent directory must already exist.
.PARAMETER LogPath
Path for a new CMTrace log. Defaults to ReportPath with the extension .log.
Its parent directory must already exist. It must differ from ReportPath.
.EXAMPLE
.\Revoke-CloudPkiLeafCertificates.ps1 -WhatIf
.EXAMPLE
.\Revoke-CloudPkiLeafCertificates.ps1 -TenantId <tenant-guid> -UseConsoleSelection -WhatIf
.EXAMPLE
.\Revoke-CloudPkiLeafCertificates.ps1 -TenantId <tenant-guid> -CaId <ca-guid> -WhatIf
.EXAMPLE
.\Revoke-CloudPkiLeafCertificates.ps1 -TenantId <tenant-guid> -CaId <ca-guid>
.NOTES
Script version: 1.1.0
1.1.0: Added CMTrace logging, including setup failures and WhatIf results.
Publication: No customer names, tenant IDs, CA IDs, credentials or user-specific
paths are embedded in this script. Supply environment-specific values only at
runtime. Generated logs and CSV reports are NOT anonymized: they can contain
tenant/CA/certificate IDs, names, UPNs, device names, paths and error details.
Do not commit these outputs or unredacted screenshots to a public repository.
Requires Microsoft.Graph.Authentication >= 2.4.0. This is a technical API baseline,
not a security recommendation to install that old release. NoWelcome first
appears in SDK 2.4.0; the REST beta endpoints do not require a generated beta module.
Source: https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/2.4.0/src/Authentication/Authentication/Cmdlets/ConnectMgGraph.cs
Installs only when missing or below the minimum, not on every run. Installation
requires PowerShellGet (Find-Module/Install-Module), PSGallery access and its
normal prerequisites. No prerequisites are silently installed or bypassed.
Windows PowerShell additionally requires .NET Framework 4.7.2 or later.
Uses Graph beta in the Global cloud, delegated authentication, admin-consented
DeviceManagementCloudCA.ReadWrite.All and DeviceManagementConfiguration.Read.All,
and an Intune role authorized to revoke leaf certificates.
The beta action documentation currently lists Configuration.Read.All while the
CA GET documentation lists CloudCA permissions; validate authorization in the
customer tenant before a production run. No permissions are granted by this script.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [guid]$TenantId = [guid]::Empty,

    [guid]$CaId = [guid]::Empty,

    [switch]$UseConsoleSelection,

    [ValidateNotNullOrEmpty()]
    [string]$ReportPath = ".\CloudPKI-Leaf-Revoke-$((Get-Date).ToString('yyyyMMdd-HHmmss-fff')).csv",

    [ValidateNotNullOrEmpty()]
    [string]$LogPath = [System.IO.Path]::ChangeExtension($ReportPath, '.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptVersion = [version]'1.1.0'
$moduleName = 'Microsoft.Graph.Authentication'
$minimumGraphVersion = [version]'2.4.0'
$logInitialized = $false

function Write-CMTraceLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateRange(1, 3)][int]$Severity = 1
    )

    $now = [DateTimeOffset]::UtcNow
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $safeMessage = ($Message -replace '[\r\n]+', ' ').Replace(']LOG]!>', ']LOG] !>')
    $line = '<![LOG[{0}]LOG]!><time="{1}+000" date="{2}" component="CloudPKI.LeafRevoke" context="" type="{3}" thread="{4}" file="Revoke-CloudPkiLeafCertificates.ps1">' -f
        $safeMessage, $now.ToString('HH:mm:ss.fff', $culture),
        $now.ToString('MM-dd-yyyy', $culture), $Severity,
        [System.Threading.Thread]::CurrentThread.ManagedThreadId
    [System.IO.File]::AppendAllText(
        $logFullPath, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true)))
}

trap {
    $fatalError = $_
    if ($logInitialized) {
        try {
            Write-CMTraceLog -Severity 3 -Message "Run stopped: $($fatalError.Exception.Message)"
        } catch [System.IO.IOException], [System.UnauthorizedAccessException] {
            Write-Warning "Cannot write fatal error to CMTrace log '$logFullPath': $($_.Exception.Message)"
        }
    }
    throw $fatalError
}

$reportFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
$logFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
if ($logFullPath -eq $reportFullPath) {
    throw 'LogPath and ReportPath must identify different files.'
}
([System.IO.File]::Open(
    $logFullPath, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)).Dispose()
$logInitialized = $true
Write-CMTraceLog -Message "Run started. ScriptVersion=$scriptVersion; WhatIf=$WhatIfPreference; Report=$reportFullPath; timestamps=UTC."
Write-Host "Cloud PKI leaf revocation script v$scriptVersion"
Write-Host "CMTrace log: $logFullPath"

if (($PSBoundParameters.ContainsKey('TenantId') -and $TenantId -eq [guid]::Empty) -or
    ($PSBoundParameters.ContainsKey('CaId') -and $CaId -eq [guid]::Empty)) {
    throw 'Explicit TenantId and CaId values must not be empty GUIDs.'
}

Write-CMTraceLog -Message "Checking $moduleName; minimum required version=$minimumGraphVersion."
$loadedModules = @(Get-Module -Name $moduleName)
if ($loadedModules.Count -gt 1) {
    throw "Multiple versions of $moduleName are loaded. Start a fresh PowerShell process and rerun."
}
if ($loadedModules.Count -eq 1 -and $loadedModules[0].Version -ge $minimumGraphVersion) {
    $graphModuleVersion = $loadedModules[0].Version
} else {
    $availableModules = @(Get-Module -ListAvailable -Name $moduleName |
        Where-Object { $_.Version -ge $minimumGraphVersion } |
        Sort-Object Version -Descending)
    if ($availableModules.Count -eq 0) {
        $installHint = "Install-Module $moduleName -MinimumVersion $minimumGraphVersion -Scope CurrentUser -Repository PSGallery"
        if ($WhatIfPreference) {
            throw "$moduleName >= $minimumGraphVersion is required. WhatIf will not install it. Run separately: $installHint"
        }
        foreach ($command in @('Find-Module', 'Install-Module')) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
                throw "Missing $command. Set up PowerShellGet first, then run: $installHint"
            }
        }
        Write-Host "$moduleName >= $minimumGraphVersion is missing. Installation is for CurrentUser; no admin rights are needed."
        Write-CMTraceLog -Severity 2 -Message "$moduleName >= $minimumGraphVersion is missing. Requesting consent for CurrentUser installation."
        $installAnswer = Read-Host "Download and install the latest stable $moduleName from PSGallery for CurrentUser? [y/N]"
        if ($installAnswer -notin @('y', 'yes')) {
            throw "Module installation declined. No Graph connection attempted. Install manually: $installHint"
        }
        $package = Find-Module -Name $moduleName -Repository PSGallery -ErrorAction Stop
        $packageVersion = [version]::new()
        if ($package.Name -ne $moduleName -or
            -not [version]::TryParse([string]$package.Version, [ref]$packageVersion) -or
            $packageVersion -lt $minimumGraphVersion) {
            throw "PSGallery did not return a stable $moduleName version >= $minimumGraphVersion."
        }
        Write-Host "Installing $moduleName $packageVersion for CurrentUser."
        Write-CMTraceLog -Message "Installing $moduleName $packageVersion from PSGallery for CurrentUser."
        Install-Module -Name $moduleName -RequiredVersion $packageVersion.ToString() `
            -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
        $availableModules = @(Get-Module -ListAvailable -Name $moduleName |
            Where-Object { $_.Version -eq $packageVersion })
        if ($availableModules.Count -eq 0) {
            throw "Installation completed but $moduleName $packageVersion was not found. Check PSModulePath."
        }
    }
    if ($loadedModules.Count -gt 0) {
        throw "$moduleName $($loadedModules[0].Version) is already loaded and too old. A suitable version is installed; start a fresh PowerShell process and rerun."
    }
    $selectedVersion = $availableModules[0].Version
    Write-CMTraceLog -Message "Importing $moduleName $selectedVersion."
    Import-Module -Name $moduleName -RequiredVersion $selectedVersion.ToString() -ErrorAction Stop
    $importedModules = @(Get-Module -Name $moduleName)
    if ($importedModules.Count -ne 1 -or $importedModules[0].Version -ne $selectedVersion) {
        throw "$moduleName did not load at the selected version $selectedVersion. Start a fresh PowerShell process."
    }
    $graphModuleVersion = $importedModules[0].Version
}
foreach ($command in @('Connect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest')) {
    if (-not (Get-Command $command -Module $moduleName -ErrorAction SilentlyContinue)) {
        throw "$moduleName $graphModuleVersion does not export $command. Repair the module in a fresh PowerShell process."
    }
}
Write-Host "$moduleName $graphModuleVersion (minimum $minimumGraphVersion)"
Write-CMTraceLog -Message "Using $moduleName $graphModuleVersion."

$scopes = @('DeviceManagementCloudCA.ReadWrite.All', 'DeviceManagementConfiguration.Read.All')
$ctx = Get-MgContext
if ($TenantId -eq [guid]::Empty -and $ctx -and
    $ctx.Environment -eq 'Global' -and $ctx.AuthType -eq 'Delegated') {
    $contextTenantId = [guid]::Empty
    if (-not [guid]::TryParse([string]$ctx.TenantId, [ref]$contextTenantId) -or
        $contextTenantId -eq [guid]::Empty) {
        throw 'The existing Graph context has no valid tenant ID.'
    }
    $TenantId = $contextTenantId
}
if (-not $ctx -or ($TenantId -ne [guid]::Empty -and $ctx.TenantId -ne $TenantId.ToString()) -or
    $ctx.Environment -ne 'Global' -or $ctx.AuthType -ne 'Delegated' -or
    @($scopes | Where-Object { $_ -notin $ctx.Scopes }).Count -gt 0) {
    $connectParameters = @{
        Scopes = $scopes
        Environment = 'Global'
        ContextScope = 'Process'
        NoWelcome = $true
    }
    if ($TenantId -ne [guid]::Empty) {
        $connectParameters['TenantId'] = $TenantId.ToString()
    }
    Write-CMTraceLog -Message "Connecting to Microsoft Graph in Global cloud; requested tenant=$TenantId."
    Connect-MgGraph @connectParameters | Out-Null
}
$ctx = Get-MgContext
if (-not $ctx -or ($TenantId -ne [guid]::Empty -and $ctx.TenantId -ne $TenantId.ToString()) -or
    $ctx.Environment -ne 'Global' -or $ctx.AuthType -ne 'Delegated' -or
    @($scopes | Where-Object { $_ -notin $ctx.Scopes }).Count -gt 0) {
    throw 'Graph context does not match the requested tenant, cloud, authentication type or scopes.'
}
$connectedTenantId = [guid]::Empty
if (-not [guid]::TryParse([string]$ctx.TenantId, [ref]$connectedTenantId) -or
    $connectedTenantId -eq [guid]::Empty) {
    throw 'Graph authentication did not return a valid tenant ID.'
}
$TenantId = $connectedTenantId
Write-Host "Connected tenant: $TenantId"
Write-CMTraceLog -Message "Verified Microsoft Graph context: tenant=$TenantId; authentication=Delegated; cloud=Global."

$base = 'https://graph.microsoft.com/beta'

function Get-GraphEntity {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Hashtable
    if ($response -isnot [System.Collections.IDictionary]) {
        throw "Expected a Graph object from $Uri."
    }
    if ($response.Contains('value')) {
        $response = $response['value']
    }
    if ($response -isnot [System.Collections.IDictionary] -or
        -not $response.Contains('id') -or -not $response['id']) {
        throw "Expected a single Graph entity with an ID from $Uri."
    }
    return $response
}

function Get-GraphCollection {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $next = $Uri
    $expectedPath = ([uri]$Uri).AbsolutePath
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    while ($next) {
        $pageUri = [uri]$next
        if (-not $pageUri.IsAbsoluteUri -or $pageUri.Scheme -ne 'https' -or
            $pageUri.Host -ne 'graph.microsoft.com' -or $pageUri.Port -ne 443 -or
            $pageUri.UserInfo -or $pageUri.Fragment -or $pageUri.AbsolutePath -ne $expectedPath) {
            throw "Unexpected Graph pagination URL: $next"
        }
        if (-not $visited.Add($next)) {
            throw "Repeated Graph pagination URL: $next"
        }
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable
        if ($response -isnot [System.Collections.IDictionary] -or
            -not $response.Contains('value') -or
            $response['value'] -isnot [System.Collections.IList]) {
            throw "Expected a Graph collection from $next."
        }
        foreach ($item in $response['value']) {
            if ($item -isnot [System.Collections.IDictionary]) {
                throw "Invalid Graph collection item from $next."
            }
            $item
        }
        $next = $null
        if ($response.Contains('@odata.nextLink')) {
            $next = [string]$response['@odata.nextLink']
        }
    }
}

if ($CaId -eq [guid]::Empty) {
    Write-CMTraceLog -Message "Loading issuing CA inventory for tenant=$TenantId."
    $availableCas = @(Get-GraphCollection -Uri "$base/deviceManagement/cloudCertificationAuthority")
    $choices = @(
        foreach ($candidate in $availableCas) {
            if ($candidate['cloudCertificationAuthorityType'] -in @(
                    'issuingCertificationAuthority', 'issuingCertificationAuthorityWithExternalRoot') -and
                $candidate['certificationAuthorityStatus'] -in @('active', 'paused')) {
                $candidateId = [guid]::Empty
                if (-not [guid]::TryParse([string]$candidate['id'], [ref]$candidateId) -or
                    $candidateId -eq [guid]::Empty) {
                    throw 'CA inventory contains an issuing CA without a valid ID.'
                }
                [pscustomobject]@{
                    Name = $candidate['displayName']
                    Id = $candidateId.ToString()
                    Type = $candidate['cloudCertificationAuthorityType']
                    Status = $candidate['certificationAuthorityStatus']
                }
            }
        }
    )
    $choices = @($choices | Sort-Object Name, Id)
    if ($choices.Count -eq 0) {
        throw "No active or paused issuing CAs found in tenant $TenantId."
    }
    Write-CMTraceLog -Message "Offering $($choices.Count) issuing CA(s) for explicit single selection."
    if (-not $UseConsoleSelection -and (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        Write-CMTraceLog -Message 'Opening Out-GridView CA selection.'
        $selected = @($choices | Out-GridView -Title "Tenant $TenantId - select one issuing CA" `
                -OutputMode Single -ErrorAction Stop)
        if ($selected.Count -ne 1) {
            throw 'CA selection cancelled; no certificates revoked.'
        }
        $selectedId = [string]$selected[0].Id
        if (@($choices | Where-Object { $_.Id -eq $selectedId }).Count -ne 1) {
            throw 'CA selection did not identify exactly one CA from the inventory.'
        }
        $CaId = [guid]$selectedId
    } else {
        Write-CMTraceLog -Message 'Using numbered console CA selection.'
        if (-not $UseConsoleSelection) {
            Write-Host 'Out-GridView is unavailable; using console selection.'
        }
        $numberedChoices = for ($index = 0; $index -lt $choices.Count; $index++) {
            [pscustomobject]@{
                Number = $index + 1
                Name = $choices[$index].Name
                Id = $choices[$index].Id
                Type = $choices[$index].Type
                Status = $choices[$index].Status
            }
        }
        $numberedChoices | Format-Table -AutoSize -Wrap | Out-Host
        $answer = Read-Host "Select one CA [1-$($choices.Count)], or press Enter to cancel"
        if ([string]::IsNullOrWhiteSpace($answer)) {
            throw 'CA selection cancelled; no certificates revoked.'
        }
        $selectionNumber = 0
        if (-not [int]::TryParse($answer, [ref]$selectionNumber) -or
            $selectionNumber -lt 1 -or $selectionNumber -gt $choices.Count) {
            throw 'Invalid CA selection; enter exactly one displayed number. No certificates revoked.'
        }
        $CaId = [guid]$choices[$selectionNumber - 1].Id
    }
}

$caUri = "$base/deviceManagement/cloudCertificationAuthority/$CaId"
$ca = Get-GraphEntity -Uri $caUri
if ($ca['id'] -ne $CaId.ToString()) {
    throw 'The returned CA ID does not match CaId.'
}
if ($ca['cloudCertificationAuthorityType'] -notin @(
        'issuingCertificationAuthority', 'issuingCertificationAuthorityWithExternalRoot')) {
    throw "Target is not an issuing CA: $($ca['cloudCertificationAuthorityType'])"
}
if ($ca['certificationAuthorityStatus'] -notin @('active', 'paused')) {
    throw "CA must be active or paused; current status: $($ca['certificationAuthorityStatus'])"
}

Write-Host "Tenant: $TenantId; CA: $($ca['displayName']) [$CaId]; status: $($ca['certificationAuthorityStatus'])"
Write-CMTraceLog -Message "Target verified: tenant=$TenantId; CA=$CaId; name=$($ca['displayName']); status=$($ca['certificationAuthorityStatus'])."

$rowTemplate = [ordered]@{
    timestamp = ''
    scriptVersion = $scriptVersion.ToString()
    graphModuleVersion = $graphModuleVersion.ToString()
    tenantId = $TenantId.ToString()
    caDisplayName = $ca['displayName']
    caId = $CaId.ToString()
    leafId = ''
    serialNumber = ''
    subjectName = ''
    userPrincipalName = ''
    deviceName = ''
    action = 'revokeLeafCertificate'
    status = ''
    error = ''
}
$writer = $null
$stream = $null
$success = 0
$failed = 0
$skipped = 0
$preview = 0
try {
    # Reserve and test the report before making any tenant changes, even in WhatIf.
    $stream = [System.IO.File]::Open(
        $reportFullPath, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    $writer = New-Object System.IO.StreamWriter($stream, (New-Object System.Text.UTF8Encoding($true)))
    $header = @([pscustomobject]$rowTemplate | ConvertTo-Csv -NoTypeInformation)[0]
    $writer.WriteLine($header)
    $writer.Flush()
    Write-Host "Report: $reportFullPath"
    Write-CMTraceLog -Message "CSV report created: $reportFullPath."

    Write-Warning 'CA remains unchanged. Certificates issued after this inventory will not be included.'
    Write-CMTraceLog -Severity 2 -Message 'CA remains unchanged. Certificates issued after this inventory will not be included.'

    $leafUri = "$caUri/cloudCertificationAuthorityLeafCertificate"
    $leafAll = @(Get-GraphCollection -Uri $leafUri)
    $leafIds = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($leaf in $leafAll) {
        $parsedId = [guid]::Empty
        if (-not [guid]::TryParse([string]$leaf['id'], [ref]$parsedId) -or
            $parsedId -eq [guid]::Empty -or -not $leafIds.Add($parsedId.ToString()) -or
            $leaf['issuerId'] -ne $CaId.ToString() -or
            $leaf['certificateStatus'] -notin @('active', 'revoked', 'expired')) {
            throw 'Invalid, duplicate, foreign or unknown-status leaf certificate in inventory; no leaves revoked.'
        }
    }
    $leafActive = @($leafAll | Where-Object { $_['certificateStatus'] -eq 'active' })
    Write-Host "Leaf certificates total: $($leafAll.Count); active: $($leafActive.Count)"
    Write-CMTraceLog -Message "Leaf inventory validated: total=$($leafAll.Count); active=$($leafActive.Count)."

    foreach ($leaf in $leafActive) {
        Write-CMTraceLog -Message "Processing leaf=$($leaf['id']); serial=$($leaf['serialNumber']); CA=$CaId."
        $row = [ordered]@{}
        foreach ($key in $rowTemplate.Keys) {
            $row[$key] = $rowTemplate[$key]
        }
        $row['timestamp'] = [DateTimeOffset]::UtcNow.ToString('o')
        foreach ($key in @('serialNumber', 'subjectName', 'userPrincipalName', 'deviceName')) {
            $row[$key] = $leaf[$key]
        }
        $row['leafId'] = $leaf['id']
        if ($PSCmdlet.ShouldProcess(
                "Tenant $TenantId; CA $CaId; leaf $($leaf['id']); serial $($leaf['serialNumber'])",
                'Irreversibly revoke leaf certificate')) {
            try {
                $body = @{ leafCertificateId = $leaf['id'] } | ConvertTo-Json
                Invoke-MgGraphRequest -Method POST -Uri "$caUri/revokeLeafCertificate" `
                    -Body $body -ContentType 'application/json' | Out-Null
                $row['status'] = 'unverified'
                Write-CMTraceLog -Message "Revocation request accepted for leaf=$($leaf['id']); checking revoked status."
                for ($attempt = 0; $attempt -lt 5; $attempt++) {
                    if ($attempt -gt 0) {
                        Start-Sleep -Seconds 2
                    }
                    $current = Get-GraphEntity -Uri "$leafUri/$($leaf['id'])"
                    if ($current['id'] -ne $leaf['id'] -or $current['issuerId'] -ne $CaId.ToString()) {
                        throw 'Revocation verification returned a different certificate or issuer.'
                    }
                    if ($current['certificateStatus'] -eq 'revoked') {
                        $row['status'] = 'revoked'
                        break
                    }
                }
                if ($row['status'] -ne 'revoked') {
                    throw 'Revocation request succeeded, but revoked status was not observed. Recheck in Intune.'
                }
                $success++
            } catch {
                if ($row['status'] -ne 'unverified') {
                    $row['status'] = 'failed'
                }
                $row['error'] = $_.Exception.Message
                $failed++
                Write-Warning "Leaf $($leaf['id']): $($row['status']): $($row['error'])"
            }
        } elseif ($WhatIfPreference) {
            $row['status'] = 'whatif'
            $preview++
        } else {
            $row['status'] = 'skipped'
            $skipped++
        }
        $csv = @([pscustomobject]$row | ConvertTo-Csv -NoTypeInformation)
        $writer.WriteLine($csv[1])
        $writer.Flush()
        $severity = 1
        if ($row['status'] -in @('failed', 'unverified')) {
            $severity = 3
        } elseif ($row['status'] -eq 'skipped') {
            $severity = 2
        }
        Write-CMTraceLog -Severity $severity -Message "Leaf=$($leaf['id']); serial=$($leaf['serialNumber']); status=$($row['status']); error=$($row['error'])"
    }
} finally {
    if ($null -ne $writer) {
        $writer.Dispose()
    } elseif ($null -ne $stream) {
        $stream.Dispose()
    }
}

Write-Host "Finished. Verified revoked: $success; failed/unverified: $failed; skipped: $skipped; WhatIf: $preview"
Write-CMTraceLog -Message "Summary: verified revoked=$success; failed/unverified=$failed; skipped=$skipped; WhatIf=$preview; report=$reportFullPath."
if ($failed -gt 0) {
    throw "$failed leaf revocation(s) failed or could not be verified. See report: $reportFullPath"
}
Write-CMTraceLog -Message 'Run completed.'
