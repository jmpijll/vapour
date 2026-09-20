$ErrorActionPreference = 'Stop'

$setupScript = Join-Path $PSScriptRoot 'setup-windivert.ps1'
$expectedDownloadUri = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
$expectedArchiveHash = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
$expectedFiles = @{
    'WinDivert.dll' = 'C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2'
    'WinDivert64.sys' = '8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2'
}

function Assert-Equal {
    param([object]$Actual, [object]$Expected, [string]$Message)
    if ($Actual -ne $Expected) {
        throw "$Message (actual: $Actual; expected: $Expected)"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-SetupTest {
    param(
        [int]$FailuresBeforeSuccess = 0,
        [switch]$ArchiveChecksumMismatch,
        [switch]$BinaryChecksumMismatch
    )

    $root = Join-Path ([IO.Path]::GetTempPath()) ('vapour-windivert-test-' + [guid]::NewGuid().ToString('N'))
    $script:downloadAttempts = 0
    $script:archivePresenceAtAttempt = @()
    $script:timeouts = @()
    $script:downloadUris = @()
    $script:backoffs = @()
    $script:downloadFailures = $FailuresBeforeSuccess
    $script:archiveMismatch = $ArchiveChecksumMismatch.IsPresent
    $script:binaryMismatch = $BinaryChecksumMismatch.IsPresent

    function Invoke-WebRequest {
        param([string]$Uri, [string]$OutFile, [int]$TimeoutSec, [switch]$UseBasicParsing)
        $script:downloadAttempts++
        $script:downloadUris += $Uri
        $script:timeouts += $TimeoutSec
        if (-not $UseBasicParsing) {
            throw 'Synthetic download did not request basic parsing'
        }
        $script:archivePresenceAtAttempt += Test-Path -LiteralPath $OutFile
        if ($script:downloadAttempts -le $script:downloadFailures) {
            Set-Content -LiteralPath $OutFile -Value 'partial archive'
            throw 'synthetic download failure'
        }
        Set-Content -LiteralPath $OutFile -Value 'synthetic archive'
    }

    function Start-Sleep {
        param([int]$Seconds)
        $script:backoffs += $Seconds
    }

    function Get-FileHash {
        param([string]$LiteralPath, [string]$Algorithm)
        $name = [IO.Path]::GetFileName($LiteralPath)
        if ($name -eq 'WinDivert.zip') {
            $hash = if ($script:archiveMismatch) { 'BAD-ARCHIVE-HASH' } else { $expectedArchiveHash }
        } else {
            $hash = if ($script:binaryMismatch) { 'BAD-BINARY-HASH' } else { $expectedFiles[$name] }
        }
        [pscustomobject]@{ Hash = $hash }
    }

    function Expand-Archive {
        param([string]$LiteralPath, [string]$DestinationPath)
        $source = Join-Path $DestinationPath 'WinDivert-2.2.2-A/x64'
        New-Item -ItemType Directory -Force -Path $source | Out-Null
        Set-Content -LiteralPath (Join-Path $source 'WinDivert.dll') -Value 'synthetic dll'
        Set-Content -LiteralPath (Join-Path $source 'WinDivert64.sys') -Value 'synthetic driver'
    }

    try {
        $caughtError = $null
        try {
            . $setupScript -RepositoryRoot $root
        } catch {
            $caughtError = $_
        }
        $resolvedRoot = [IO.Path]::GetFullPath($root)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $resolvedRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Synthetic cleanup root escaped the temp directory'
        }
        if ([IO.Path]::GetFileName($resolvedRoot) -notlike 'vapour-windivert-test-*') {
            throw 'Synthetic cleanup root had an unexpected name'
        }
        [pscustomobject]@{
            Root = $root
            Error = $caughtError
            Attempts = $script:downloadAttempts
            ArchivePresenceAtAttempt = $script:archivePresenceAtAttempt
            Timeouts = $script:timeouts
            DownloadUris = $script:downloadUris
            Backoffs = $script:backoffs
            StagedDll = Test-Path -LiteralPath (Join-Path $root 'src-tauri/vendor/windivert/WinDivert.dll')
            StagedSys = Test-Path -LiteralPath (Join-Path $root 'src-tauri/vendor/windivert/WinDivert64.sys')
            Destination = Join-Path $root 'src-tauri/vendor/windivert'
        }
    } finally {
        $resolvedRoot = [IO.Path]::GetFullPath($root)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (Test-Path -LiteralPath $resolvedRoot) {
            if (-not $resolvedRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolvedRoot) -notlike 'vapour-windivert-test-*') {
                throw 'Refusing to remove an unexpected synthetic root'
            }
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    }
}

$transient = Invoke-SetupTest -FailuresBeforeSuccess 2
Assert-Equal $transient.Error $null 'Transient failures should recover'
Assert-Equal $transient.Attempts 3 'Transient failures should use three attempts'
Assert-Equal $transient.ArchivePresenceAtAttempt[0] $false 'First attempt should start without an archive'
Assert-Equal $transient.ArchivePresenceAtAttempt[1] $false 'Retry should remove the partial archive'
Assert-Equal $transient.ArchivePresenceAtAttempt[2] $false 'Final attempt should start without an archive'
Assert-True (($transient.Timeouts | Where-Object { $_ -ne 60 }).Count -eq 0) 'Each download attempt should have a 60 second timeout'
Assert-True (($transient.DownloadUris | Where-Object { $_ -ne $expectedDownloadUri }).Count -eq 0) 'Each attempt should use the pinned download URI'
Assert-Equal ($transient.Backoffs -join ',') '2,4' 'Transient failures should use bounded backoff'
Assert-True $transient.StagedDll 'Successful download should stage WinDivert.dll'
Assert-True $transient.StagedSys 'Successful download should stage WinDivert64.sys'

$exhausted = Invoke-SetupTest -FailuresBeforeSuccess 3
Assert-True ($null -ne $exhausted.Error) 'Exhausted download attempts should fail'
Assert-Equal $exhausted.Attempts 3 'Exhausted download should stop after three attempts'
Assert-Equal ($exhausted.Backoffs -join ',') '2,4' 'Exhausted download should use bounded backoff'
Assert-True (-not $exhausted.StagedDll -and -not $exhausted.StagedSys) 'Exhausted download must not stage files'

$archiveMismatch = Invoke-SetupTest -ArchiveChecksumMismatch
Assert-True ($null -ne $archiveMismatch.Error) 'Archive checksum mismatch should fail'
Assert-Equal $archiveMismatch.Attempts 1 'Archive checksum mismatch must not retry'
Assert-Equal $archiveMismatch.Backoffs.Count 0 'Archive checksum mismatch must not back off'
Assert-True (-not $archiveMismatch.StagedDll -and -not $archiveMismatch.StagedSys) 'Archive checksum mismatch must not stage files'

$binaryMismatch = Invoke-SetupTest -BinaryChecksumMismatch
Assert-True ($null -ne $binaryMismatch.Error) 'Binary checksum mismatch should fail'
Assert-Equal $binaryMismatch.Attempts 1 'Binary checksum mismatch must not retry'
Assert-Equal $binaryMismatch.Backoffs.Count 0 'Binary checksum mismatch must not back off'
Assert-True (-not $binaryMismatch.StagedDll -and -not $binaryMismatch.StagedSys) 'Binary checksum mismatch must not stage files'

Write-Host 'setup-windivert regression tests passed.'
