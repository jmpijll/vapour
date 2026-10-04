param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Commit
)
$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location $taskRoot
try {
    $taskHead = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -or $taskHead -ne $Commit) { throw 'Package must match the checked-out commit' }
    $taskDirty = & git status --porcelain --untracked-files=no
    if ($LASTEXITCODE -or $taskDirty) {
        $taskDirty | Write-Output
        & git diff --stat
        throw 'Tracked source changed after checkout'
    }
    $taskExe = (Resolve-Path -LiteralPath $Executable).Path
    $taskDestination = Join-Path $taskRoot 'outputs/nightly'
    if ((Test-Path -LiteralPath $taskDestination) -or (Test-Path -LiteralPath 'outputs/nightly-package')) { throw 'Nightly output already exists' }
    $taskPackage = New-Item -ItemType Directory -Path (Join-Path $taskRoot 'outputs/nightly-package')
    $null = New-Item -ItemType Directory -Path $taskDestination
    $taskInfoFile = Join-Path $taskPackage.FullName 'build-info.json'
    $taskInfoProcess = Start-Process -FilePath $taskExe -ArgumentList '--vapour-build-info' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $taskInfoFile
    $taskInfo = Get-Content -LiteralPath $taskInfoFile -Raw | ConvertFrom-Json
    if ($taskInfoProcess.ExitCode -ne 0 -or $taskInfo.product -ne 'Vapour' -or
        $taskInfo.architecture -ne 'x86_64' -or $taskInfo.custom_protocol -ne $true -or
        $taskInfo.capture_enabled -ne $false) { throw 'Expected embedded Windows x64 nightly with capture disabled' }
    Copy-Item -LiteralPath $taskExe -Destination (Join-Path $taskPackage.FullName 'Vapour.exe')
    foreach ($taskNotice in @('LICENSE', 'THIRD_PARTY.md', 'docs/TESTING.md')) {
        Copy-Item -LiteralPath (Join-Path $taskRoot $taskNotice) -Destination $taskPackage.FullName
    }
    $taskSource = Join-Path $taskPackage.FullName 'source.zip'
    & git archive --format=zip --output=$taskSource $Commit
    if ($LASTEXITCODE) { throw 'Cannot archive corresponding source' }
    $taskUpstream = Join-Path $taskPackage.FullName 'WinDivert-v2.2.2-source.zip'
    Invoke-WebRequest -Uri 'https://codeload.github.com/basil00/WinDivert/zip/1789526ecfb9ff5397c94f9f54c1a3dc2fb60440' -OutFile $taskUpstream
    $taskUpstreamHash = (Get-FileHash -LiteralPath $taskUpstream -Algorithm SHA256).Hash
    if ($taskUpstreamHash -ne '25054821D47EC0EF2227C79F3D6688A3A11D6A128D8F103710D1022E92EA1054') { throw 'WinDivert corresponding source checksum mismatch' }
    $taskMetadata = [ordered]@{
        commit = $Commit
        channel = 'nightly'
        platform = 'windows-x64'
        version = $taskInfo.version
        signed = $false
        captureEnabled = $taskInfo.capture_enabled
        nativeDriverAccepted = $false
        executableSha256 = (Get-FileHash -LiteralPath (Join-Path $taskPackage.FullName 'Vapour.exe') -Algorithm SHA256).Hash
        sourceSha256 = (Get-FileHash -LiteralPath $taskSource -Algorithm SHA256).Hash
        upstreamSourceSha256 = $taskUpstreamHash
    }
    $taskMetadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskDestination 'release.json') -Encoding utf8NoBOM
    Copy-Item -LiteralPath (Join-Path $taskDestination 'release.json') -Destination $taskPackage.FullName
    $taskZip = Join-Path $taskDestination 'Vapour-windows-x64.zip'
    Compress-Archive -Path (Join-Path $taskPackage.FullName '*') -DestinationPath $taskZip
    $taskChecksums = foreach ($taskName in @('Vapour-windows-x64.zip', 'release.json')) {
        '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path $taskDestination $taskName) -Algorithm SHA256).Hash.ToLowerInvariant(), $taskName
    }
    $taskChecksums | Set-Content -LiteralPath (Join-Path $taskDestination 'SHA256SUMS.txt') -Encoding utf8NoBOM
} finally { Pop-Location }
