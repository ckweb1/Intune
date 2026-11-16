#Requires -Version 5.1
# Tenant, CA and device values are synthetic fixtures, not customer data.
# Module operations, Graph, UI and prompts are mocked; no tenant is contacted.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'Revoke-CloudPkiLeafCertificates.ps1'
$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw ($parseErrors | Out-String)
}

$tenant = '11111111-1111-1111-1111-111111111111'
$caId = '22222222-2222-2222-2222-222222222222'
$leafId = '33333333-3333-3333-3333-333333333333'
$root = 'https://graph.microsoft.com/beta/deviceManagement/cloudCertificationAuthority'
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "CloudPkiTests-$([guid]::NewGuid())"
$null = [System.IO.Directory]::CreateDirectory($tempDir)
$script:state = @{}
$script:passed = 0

# These mocks shadow the Graph SDK; the test process never contacts Graph.
function Get-Command {
    [CmdletBinding()]
    param([string]$Name, [string]$Module)
    if ($Module -eq 'Microsoft.Graph.Authentication') {
        return Microsoft.PowerShell.Core\Get-Command -Name $Name -CommandType Function -ErrorAction Stop
    }
    Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}

function Get-Module {
    param([string]$Name, [switch]$ListAvailable)
    if ($Name -ne 'Microsoft.Graph.Authentication') { throw "Unexpected module lookup: $Name" }
    if ($ListAvailable) {
        foreach ($version in $global:CloudPkiOfflineTestState.AvailableVersions) {
            [pscustomobject]@{ Name = $Name; Version = $version }
        }
    } elseif ($null -ne $global:CloudPkiOfflineTestState.LoadedVersion) {
        [pscustomobject]@{ Name = $Name; Version = $global:CloudPkiOfflineTestState.LoadedVersion }
    }
}

function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$RequiredVersion)
    if ($Name -ne 'Microsoft.Graph.Authentication') { throw "Unexpected module import: $Name" }
    $global:CloudPkiOfflineTestState.Imports++
    $global:CloudPkiOfflineTestState.LoadedVersion = [version]$RequiredVersion
}

function Find-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$Repository)
    if ($Name -ne 'Microsoft.Graph.Authentication' -or $Repository -ne 'PSGallery') {
        throw 'Unexpected module source.'
    }
    $global:CloudPkiOfflineTestState.Finds++
    [pscustomobject]@{ Name = $Name; Version = $global:CloudPkiOfflineTestState.PublishedVersion }
}

function Install-Module {
    [CmdletBinding()]
    param([string]$Name, [string]$RequiredVersion, [string]$Scope, [string]$Repository)
    $global:CloudPkiOfflineTestState.Installs++
    if ($Name -ne 'Microsoft.Graph.Authentication' -or $Repository -ne 'PSGallery' -or $Scope -ne 'CurrentUser') {
        throw 'Unexpected installation package, source or scope.'
    }
    if ($global:CloudPkiOfflineTestState.InstallFails) { throw 'Simulated installation failure.' }
    if (-not $global:CloudPkiOfflineTestState.InstallNoOp) {
        $global:CloudPkiOfflineTestState.AvailableVersions += [version]$RequiredVersion
    }
}

function Get-MgContext {
    $global:CloudPkiOfflineTestState.Context
}

function Connect-MgGraph {
    param($TenantId, $Scopes, $Environment, $ContextScope, [switch]$NoWelcome)
    $global:CloudPkiOfflineTestState.Connects++
    $global:CloudPkiOfflineTestState.ConnectTenantId = $TenantId
    if (-not $global:CloudPkiOfflineTestState.BadTenant) {
        if (-not $TenantId) { $TenantId = $global:CloudPkiOfflineTestState.LoginTenant }
        $global:CloudPkiOfflineTestState.Context = @{
            TenantId = $TenantId
            Scopes = $Scopes
            Environment = $Environment
            AuthType = 'Delegated'
        }
    }
}

function Start-Sleep {
    param($Seconds)
}

function Out-GridView {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]$InputObject,
        [string]$Title,
        [ValidateSet('Single')][string]$OutputMode
    )
    begin { $items = New-Object 'System.Collections.Generic.List[object]' }
    process { $items.Add($InputObject) }
    end {
        $global:CloudPkiOfflineTestState.GridCalls++
        $global:CloudPkiOfflineTestState.GridChoices = @($items.ToArray())
        $global:CloudPkiOfflineTestState.GridTitle = $Title
        if (-not $global:CloudPkiOfflineTestState.CancelGrid) {
            $items | Where-Object { $_.Id -eq $global:CloudPkiOfflineTestState.ExpectedCaId }
        }
    }
}

function Read-Host {
    param($Prompt)
    if ($Prompt -like 'Download and install*') {
        $global:CloudPkiOfflineTestState.InstallPrompts++
        return $global:CloudPkiOfflineTestState.InstallAnswer
    }
    $global:CloudPkiOfflineTestState.ConsoleCalls++
    $global:CloudPkiOfflineTestState.ConsoleAnswer
}

function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $Body, $ContentType)
    $caId = $global:CloudPkiOfflineTestState.ExpectedCaId
    if ($Method -eq 'POST') {
        $global:CloudPkiOfflineTestState.Posts++
        if ($Uri -ne "$root/$caId/revokeLeafCertificate") {
            throw "FORBIDDEN non-leaf mutation: $Uri"
        }
        $payload = $Body | ConvertFrom-Json
        if (@($payload.PSObject.Properties).Count -ne 1 -or $payload.leafCertificateId -ne $leafId) {
            throw 'Unexpected leaf mutation payload.'
        }
        if ($global:CloudPkiOfflineTestState.PostFails) {
            throw $global:CloudPkiOfflineTestState.PostFailureMessage
        }
        return @{ value = @{ id = $leafId; certificateStatus = 'active' } }
    }
    if ($Method -ne 'GET' -or $OutputType -ne 'Hashtable') {
        throw "Unexpected request: $Method $Uri"
    }
    if ($Uri -eq $root) {
        if ($global:CloudPkiOfflineTestState.PaginateCas) {
            return @{ value = @(); '@odata.nextLink' = "$root`?`$skiptoken=cas2" }
        }
        return @{ value = @($global:CloudPkiOfflineTestState.Cas) }
    }
    if ($Uri -eq "$root`?`$skiptoken=cas2") {
        return @{ value = @($global:CloudPkiOfflineTestState.Cas) }
    }
    if ($Uri -eq "$root/$caId") {
        $ca = @{
            id = $caId
            displayName = 'Test issuing CA'
            cloudCertificationAuthorityType = $global:CloudPkiOfflineTestState.CaType
            certificationAuthorityStatus = 'active'
        }
        if ($global:CloudPkiOfflineTestState.WrappedCa) { return @{ value = $ca } }
        return $ca
    }
    if ($Uri -eq "$root/$caId/cloudCertificationAuthorityLeafCertificate/$leafId") {
        $global:CloudPkiOfflineTestState.Verifications++
        return @{
            id = $leafId
            issuerId = $caId
            certificateStatus = $global:CloudPkiOfflineTestState.VerificationStatus
        }
    }
    if ($Uri -eq "$root/$caId/cloudCertificationAuthorityLeafCertificate") {
        if ($global:CloudPkiOfflineTestState.LockLogOnInventory) {
            $global:CloudPkiOfflineTestState.LogLock = [System.IO.File]::Open(
                $global:CloudPkiOfflineTestState.LogFile, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        if ($global:CloudPkiOfflineTestState.Paginate) {
            return @{
                value = @()
                '@odata.nextLink' = "$root/$caId/cloudCertificationAuthorityLeafCertificate?`$skiptoken=page2"
            }
        }
        if ($global:CloudPkiOfflineTestState.BadNextLink) {
            return @{ value = @(); '@odata.nextLink' = 'https://example.invalid/collect' }
        }
        if ($global:CloudPkiOfflineTestState.Malformed) { return @{ value = $null } }
        return @{ value = @($global:CloudPkiOfflineTestState.Leaves) }
    }
    if ($Uri -eq "$root/$caId/cloudCertificationAuthorityLeafCertificate?`$skiptoken=page2") {
        return @{ value = @($global:CloudPkiOfflineTestState.Leaves) }
    }
    throw "Unexpected GET: $Uri"
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-Case {
    param(
        [string]$Name, [scriptblock]$Arrange, [scriptblock]$Assert,
        [switch]$Preview, [switch]$ExpectError, [switch]$AutoTenant,
        [switch]$SelectCa, [switch]$Console
    )

    $script:state = @{
        LoadedVersion = [version]'2.4.0'
        AvailableVersions = @([version]'2.4.0')
        PublishedVersion = '2.41.2'
        InstallAnswer = 'n'
        InstallPrompts = 0
        Installs = 0
        Finds = 0
        Imports = 0
        InstallFails = $false
        InstallNoOp = $false
        LogPathOverride = $null
        PreserveLog = $false
        SkipLogValidation = $false
        AllowMissingFatalLog = $false
        LockLogOnInventory = $false
        LogLock = $null
        LogFile = ''
        Context = @{
            TenantId = $tenant
            Scopes = @('DeviceManagementCloudCA.ReadWrite.All', 'DeviceManagementConfiguration.Read.All')
            Environment = 'Global'
            AuthType = 'Delegated'
        }
        Connects = 0
        ConnectTenantId = $null
        LoginTenant = $tenant
        ExpectedCaId = $caId
        Posts = 0
        Verifications = 0
        BadTenant = $false
        PostFails = $false
        PostFailureMessage = 'Simulated HTTP 403.'
        WrappedCa = $false
        Paginate = $false
        BadNextLink = $false
        Malformed = $false
        CaType = 'issuingCertificationAuthority'
        GridCalls = 0
        GridChoices = @()
        GridTitle = ''
        CancelGrid = $false
        ConsoleCalls = 0
        ConsoleAnswer = '1'
        PaginateCas = $false
        Cas = @(
            @{
                id = $caId
                displayName = 'Test issuing CA'
                cloudCertificationAuthorityType = 'issuingCertificationAuthority'
                certificationAuthorityStatus = 'active'
            },
            @{
                id = '77777777-7777-7777-7777-777777777777'
                displayName = 'Root CA'
                cloudCertificationAuthorityType = 'rootCertificationAuthority'
                certificationAuthorityStatus = 'active'
            },
            @{
                id = '88888888-8888-8888-8888-888888888888'
                displayName = 'Revoked issuing CA'
                cloudCertificationAuthorityType = 'issuingCertificationAuthority'
                certificationAuthorityStatus = 'revoked'
            }
        )
        VerificationStatus = 'revoked'
        Leaves = @(@{
            id = $leafId
            issuerId = $caId
            certificateStatus = 'active'
            serialNumber = 'ABC123'
            subjectName = 'CN=Test'
            userPrincipalName = $null
            deviceName = 'Device,One'
        })
    }
    $global:CloudPkiOfflineTestState = $script:state
    $report = Join-Path $tempDir "$Name.csv"
    & $Arrange
    $log = [System.IO.Path]::ChangeExtension($report, '.log')
    if ($script:state.LogPathOverride) { $log = $script:state.LogPathOverride }
    $script:state.LogFile = $log
    $caught = $null
    try {
        $arguments = @{
            ReportPath = $report
            Confirm = $false
            WhatIf = [bool]$Preview
            UseConsoleSelection = [bool]$Console
        }
        if ($script:state.LogPathOverride) { $arguments['LogPath'] = $script:state.LogPathOverride }
        if (-not $AutoTenant) { $arguments['TenantId'] = $tenant }
        if (-not $SelectCa) { $arguments['CaId'] = $caId }
        & $target @arguments
    } catch {
        $caught = $_
    } finally {
        if ($null -ne $script:state.LogLock) {
            $script:state.LogLock.Dispose()
        }
    }
    if ($ExpectError) {
        Assert-True ($null -ne $caught) "$Name should have thrown."
    } elseif ($null -ne $caught) {
        throw "$Name failed: $caught"
    }
    if (-not $script:state.SkipLogValidation -and -not $script:state.PreserveLog) {
        Assert-True (Test-Path -LiteralPath $log -PathType Leaf) "$Name did not create its CMTrace log."
        $entries = [System.IO.File]::ReadAllLines($log)
        Assert-True ($entries.Count -gt 0) "$Name log is empty."
        $entryPattern = '^<!\[LOG\[(?<Message>.*)\]LOG\]!><time="\d{2}:\d{2}:\d{2}\.\d{3}\+000" date="\d{2}-\d{2}-\d{4}" component="CloudPKI\.LeafRevoke" context="" type="[123]" thread="\d+" file="Revoke-CloudPkiLeafCertificates\.ps1">$'
        foreach ($entry in $entries) {
            Assert-True ($entry -match $entryPattern) "$Name contains an invalid CMTrace entry: $entry"
        }
        if ($ExpectError -and -not $script:state.AllowMissingFatalLog) {
            Assert-True (($entries -match 'Run stopped:.*type="3"').Count -gt 0) "$Name omitted its fatal error from the log."
        } elseif (-not $ExpectError) {
            Assert-True ($entries[-1] -match 'Run completed\.') "$Name log has no completion entry."
        }
    }
    & $Assert $report $caught
    $script:passed++
    Write-Host "PASS: $Name"
}

try {
    Invoke-Case 'single-active' {} {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($script:state.Posts -eq 1 -and $script:state.Connects -eq 0) 'Wrong mutation or reconnect count.'
        Assert-True ($rows.Count -eq 1 -and $rows[0].status -eq 'revoked') 'Missing verified result.'
        Assert-True ($rows[0].deviceName -eq 'Device,One') 'CSV escaping failed.'
        Assert-True ($rows[0].scriptVersion -eq '1.1.0' -and $rows[0].graphModuleVersion -eq '2.4.0') 'Version metadata missing.'
        Assert-True ($script:state.Installs -eq 0 -and $script:state.Finds -eq 0) 'Supported module triggered an update.'
        $logText = [System.IO.File]::ReadAllText([System.IO.Path]::ChangeExtension($Report, '.log'))
        Assert-True ($logText -match 'ScriptVersion=1\.1\.0' -and $logText -match "tenant=$tenant" -and $logText -match "CA=$caId") 'Log lacks run version or target.'
        Assert-True ($logText -match "Leaf=$leafId; serial=ABC123; status=revoked" -and $logText -match 'verified revoked=1') 'Log lacks verified leaf result or summary.'
        Assert-True ($logText -match 'type="1"' -and $logText -match 'type="2"') 'Information or warning severity missing.'
    }
    Invoke-Case 'whatif' {} {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($script:state.Posts -eq 0 -and $script:state.Verifications -eq 0) 'WhatIf mutated Graph.'
        Assert-True ($rows.Count -eq 1 -and $rows[0].status -eq 'whatif') 'WhatIf report missing.'
        $logText = [System.IO.File]::ReadAllText([System.IO.Path]::ChangeExtension($Report, '.log'))
        Assert-True ($logText -match "Leaf=$leafId; serial=ABC123; status=whatif" -and $logText -notmatch 'Revocation request accepted') 'WhatIf log is incorrect.'
    } -Preview
    Invoke-Case 'empty' { $script:state.Leaves = @() } {
        param($Report)
        Assert-True ($script:state.Posts -eq 0) 'Empty inventory mutated Graph.'
        Assert-True ((@(Import-Csv -LiteralPath $Report)).Count -eq 0) 'Empty inventory produced rows.'
        Assert-True ((Get-Content -LiteralPath $Report -TotalCount 1) -match '"leafId"') 'Header missing.'
    }
    Invoke-Case 'empty-page-with-next' { $script:state.Paginate = $true; $script:state.WrappedCa = $true } {
        Assert-True ($script:state.Posts -eq 1) 'Pagination lost the active leaf.'
    }
    Invoke-Case 'inactive-skipped' {
        $inactive = $script:state.Leaves[0].Clone()
        $inactive.id = '44444444-4444-4444-4444-444444444444'
        $inactive.certificateStatus = 'expired'
        $script:state.Leaves += $inactive
        $revoked = $inactive.Clone()
        $revoked.id = '55555555-5555-5555-5555-555555555555'
        $revoked.certificateStatus = 'revoked'
        $script:state.Leaves += $revoked
    } {
        Assert-True ($script:state.Posts -eq 1) 'Inactive certificates were submitted.'
    }
    Invoke-Case 'wrong-tenant' {
        $script:state.Context.TenantId = '99999999-9999-9999-9999-999999999999'
        $script:state.BadTenant = $true
    } {
        Assert-True ($script:state.Connects -eq 1 -and $script:state.Posts -eq 0) 'Tenant guard failed.'
    } -ExpectError
    Invoke-Case 'missing-scope' { $script:state.Context.Scopes = @() } {
        Assert-True ($script:state.Connects -eq 1 -and $script:state.Posts -eq 1) 'Scope reconnection failed.'
    }
    Invoke-Case 'foreign-leaf' { $script:state.Leaves[0].issuerId = $tenant } {
        Assert-True ($script:state.Posts -eq 0) 'Foreign certificate was submitted.'
    } -ExpectError
    Invoke-Case 'root-ca' { $script:state.CaType = 'rootCertificationAuthority' } {
        Assert-True ($script:state.Posts -eq 0) 'Root CA accepted.'
    } -ExpectError
    Invoke-Case 'existing-report' { [System.IO.File]::WriteAllText($report, 'preserve-me') } {
        param($Report)
        Assert-True ($script:state.Posts -eq 0) 'Mutation happened before report validation.'
        Assert-True ([System.IO.File]::ReadAllText($Report) -eq 'preserve-me') 'Existing report overwritten.'
    } -ExpectError
    Invoke-Case 'failed-post' { $script:state.PostFails = $true } {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($rows[0].status -eq 'failed' -and $rows[0].error -match '403') 'Failure not reported.'
    } -ExpectError
    Invoke-Case 'unverified' { $script:state.VerificationStatus = 'active' } {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($rows[0].status -eq 'unverified' -and $script:state.Verifications -eq 5) 'Unverified request reported as revoked.'
    } -ExpectError
    Invoke-Case 'bad-nextlink' { $script:state.BadNextLink = $true } {
        Assert-True ($script:state.Posts -eq 0) 'Unexpected pagination URL accepted.'
    } -ExpectError
    Invoke-Case 'malformed-collection' { $script:state.Malformed = $true } {
        Assert-True ($script:state.Posts -eq 0) 'Malformed collection accepted.'
    } -ExpectError
    Invoke-Case 'tenant-from-context' {} {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($script:state.Connects -eq 0 -and $rows[0].tenantId -eq $tenant) 'Existing tenant was not reused.'
    } -AutoTenant
    Invoke-Case 'tenant-from-login' { $script:state.Context = $null } {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($script:state.Connects -eq 1 -and -not $script:state.ConnectTenantId) 'Unspecified tenant was forced at login.'
        Assert-True ($rows[0].tenantId -eq $tenant) 'Logged-in tenant not used.'
    } -AutoTenant
    Invoke-Case 'inferred-tenant-pinned-on-reconnect' { $script:state.Context.Scopes = @() } {
        Assert-True ($script:state.Connects -eq 1 -and $script:state.ConnectTenantId -eq $tenant) 'Scope reconnect changed tenant.'
    } -AutoTenant
    Invoke-Case 'grid-selection' { $script:state.PaginateCas = $true } {
        Assert-True ($script:state.GridCalls -eq 1 -and $script:state.Posts -eq 1) 'Grid selection failed.'
        Assert-True ($script:state.GridChoices.Count -eq 1) 'Root or revoked CA was offered.'
        Assert-True ($script:state.GridTitle -match $tenant) 'Grid omitted tenant ID.'
    } -AutoTenant -SelectCa
    Invoke-Case 'grid-cancelled' { $script:state.CancelGrid = $true } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and -not (Test-Path -LiteralPath $Report)) 'Cancel caused changes.'
        Assert-True ($Caught.Exception.Message -match 'cancelled') 'Cancellation reason missing.'
    } -SelectCa -ExpectError
    Invoke-Case 'console-selection' {
        $script:state.Cas += @{
            id = '66666666-6666-6666-6666-666666666666'
            displayName = 'A external issuing CA'
            cloudCertificationAuthorityType = 'issuingCertificationAuthorityWithExternalRoot'
            certificationAuthorityStatus = 'paused'
        }
        $script:state.ConsoleAnswer = '2'
    } {
        Assert-True ($script:state.ConsoleCalls -eq 1 -and $script:state.GridCalls -eq 0) 'Console was not used.'
        Assert-True ($script:state.Posts -eq 1) 'Console selected wrong CA.'
    } -SelectCa -Console
    Invoke-Case 'console-cancelled' { $script:state.ConsoleAnswer = '' } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and $Caught.Exception.Message -match 'cancelled') 'Console cancel failed.'
    } -SelectCa -Console -ExpectError
    Invoke-Case 'console-invalid-number' { $script:state.ConsoleAnswer = '2' } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and $Caught.Exception.Message -match 'Invalid CA selection') 'Invalid selection accepted.'
    } -SelectCa -Console -ExpectError
    Invoke-Case 'no-issuing-ca' { $script:state.Cas = @($script:state.Cas[1]) } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and $script:state.GridCalls -eq 0) 'Empty selection opened grid or changed Graph.'
        Assert-True ($Caught.Exception.Message -match 'No active or paused issuing CAs') 'Missing no-CA message.'
    } -SelectCa -ExpectError
    Invoke-Case 'interactive-whatif' {} {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($script:state.Posts -eq 0 -and $script:state.GridCalls -eq 1) 'Interactive WhatIf changed Graph.'
        Assert-True ($rows[0].status -eq 'whatif') 'Interactive preview report incorrect.'
    } -AutoTenant -SelectCa -Preview
    Invoke-Case 'installed-module-imported' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @([version]'2.4.0', [version]'2.5.0')
    } {
        Assert-True ($script:state.Imports -eq 1 -and $script:state.LoadedVersion -eq [version]'2.5.0') 'Highest installed version not selected.'
        Assert-True ($script:state.Installs -eq 0 -and $script:state.Finds -eq 0) 'Unnecessary module installation.'
    }
    Invoke-Case 'missing-module-whatif' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @()
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Installs -eq 0 -and $script:state.Finds -eq 0 -and $script:state.InstallPrompts -eq 0) 'WhatIf bootstrapped modules.'
        Assert-True ($script:state.Posts -eq 0 -and $Caught.Exception.Message -match 'WhatIf will not install') 'WhatIf dependency guard failed.'
    } -Preview -ExpectError
    Invoke-Case 'module-install-declined' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @()
    } {
        param($Report, $Caught)
        Assert-True ($script:state.InstallPrompts -eq 1 -and $script:state.Installs -eq 0) 'Declined installation proceeded.'
        Assert-True ($script:state.Connects -eq 0 -and $script:state.Posts -eq 0 -and $Caught.Exception.Message -match 'declined') 'Declined setup did not stop safely.'
    } -ExpectError
    Invoke-Case 'module-installed-currentuser' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @()
        $script:state.InstallAnswer = 'y'
    } {
        param($Report)
        $rows = @(Import-Csv -LiteralPath $Report)
        Assert-True ($script:state.Installs -eq 1 -and $script:state.Imports -eq 1) 'Module not installed and imported.'
        Assert-True ($rows[0].graphModuleVersion -eq '2.41.2' -and $script:state.Posts -eq 1) 'Installed module version not used.'
    }
    Invoke-Case 'old-unloaded-module-updated' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @([version]'2.3.0')
        $script:state.InstallAnswer = 'yes'
    } {
        Assert-True ($script:state.Installs -eq 1 -and $script:state.LoadedVersion -eq [version]'2.41.2') 'Old version not updated.'
    }
    Invoke-Case 'old-loaded-module-requires-restart' {
        $script:state.LoadedVersion = [version]'2.3.0'
        $script:state.AvailableVersions = @([version]'2.3.0')
        $script:state.InstallAnswer = 'y'
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Installs -eq 1 -and $script:state.Imports -eq 0) 'Old assemblies were reloaded.'
        Assert-True ($script:state.Posts -eq 0 -and $Caught.Exception.Message -match 'fresh PowerShell process') 'Restart guard failed.'
    } -ExpectError
    Invoke-Case 'installation-failed' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @()
        $script:state.InstallAnswer = 'y'
        $script:state.InstallFails = $true
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and $script:state.Imports -eq 0) 'Installation failure ignored.'
        Assert-True ($Caught.Exception.Message -match 'Simulated installation failure') 'Installation error lost.'
    } -ExpectError
    Invoke-Case 'installation-not-discoverable' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @()
        $script:state.InstallAnswer = 'y'
        $script:state.InstallNoOp = $true
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and $Caught.Exception.Message -match 'was not found') 'Unverified installation accepted.'
    } -ExpectError
    Invoke-Case 'gallery-version-too-old' {
        $script:state.LoadedVersion = $null
        $script:state.AvailableVersions = @()
        $script:state.InstallAnswer = 'y'
        $script:state.PublishedVersion = '2.3.0'
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Installs -eq 0 -and $Caught.Exception.Message -match 'did not return a stable') 'Unsupported Gallery version installed.'
    } -ExpectError
    Invoke-Case 'custom-log-path' {
        $script:state.LogPathOverride = Join-Path $tempDir 'custom-output.log'
    } {
        param($Report)
        Assert-True (Test-Path -LiteralPath $script:state.LogPathOverride) 'Custom log path not used.'
        Assert-True (-not (Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($Report, '.log')))) 'Unexpected default log created.'
    }
    Invoke-Case 'existing-log' {
        $script:state.PreserveLog = $true
        [System.IO.File]::WriteAllText([System.IO.Path]::ChangeExtension($report, '.log'), 'preserve-log')
    } {
        param($Report)
        Assert-True ($script:state.Posts -eq 0 -and $script:state.Installs -eq 0) 'Log preflight did not precede mutations.'
        Assert-True ([System.IO.File]::ReadAllText([System.IO.Path]::ChangeExtension($Report, '.log')) -eq 'preserve-log') 'Existing log overwritten.'
    } -ExpectError
    Invoke-Case 'log-equals-report' {
        $script:state.LogPathOverride = $report
        $script:state.SkipLogValidation = $true
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and -not (Test-Path -LiteralPath $Report)) 'Log/report collision caused changes.'
        Assert-True ($Caught.Exception.Message -match 'different files') 'Missing log/report collision error.'
    } -ExpectError
    Invoke-Case 'log-write-failure' {
        $script:state.LockLogOnInventory = $true
        $script:state.AllowMissingFatalLog = $true
    } {
        param($Report, $Caught)
        Assert-True ($script:state.Posts -eq 0 -and $null -ne $Caught) 'Log write failure did not stop before revocation.'
    } -ExpectError
    Invoke-Case 'error-log-framing' {
        $script:state.PostFails = $true
        $script:state.PostFailureMessage = "Simulated HTTP 403.`r`nInjected ]LOG]!> text."
    } {
        param($Report)
        $entries = [System.IO.File]::ReadAllLines([System.IO.Path]::ChangeExtension($Report, '.log'))
        Assert-True (($entries -match 'status=failed; error=Simulated HTTP 403\. Injected \]LOG\] !> text\..*type="3"').Count -eq 1) 'Error log framing or severity is incorrect.'
    } -ExpectError
    Write-Host "All $script:passed offline tests passed."
} finally {
    Remove-Variable -Name CloudPkiOfflineTestState -Scope Global
    foreach ($file in [System.IO.Directory]::GetFiles($tempDir)) {
        [System.IO.File]::Delete($file)
    }
    [System.IO.Directory]::Delete($tempDir)
}
