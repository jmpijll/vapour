param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$Destination
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$binary = Get-Item -LiteralPath $Executable
if ($binary.PSIsContainer -or $binary.Length -eq 0) { throw 'Expected a nonempty standalone executable' }
if (Test-Path -LiteralPath $Destination) { throw 'Review destination must not already exist' }
$revision = & git -C $repo rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify source revision' }
$dirty = & git -C $repo status --porcelain --untracked-files=normal
if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'Package only a clean checkout so the source archive matches the build' }
$directory = New-Item -ItemType Directory -Path $Destination
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $directory.FullName 'Vapour.exe')
foreach ($name in @('LICENSE', 'THIRD_PARTY.md')) {
    Copy-Item -LiteralPath (Join-Path $repo $name) -Destination $directory.FullName
}
Copy-Item -LiteralPath (Join-Path $repo 'docs/TESTING.md') -Destination $directory.FullName
$source = Join-Path $directory.FullName 'source.zip'
& git -C $repo archive --format=zip --output=$source HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot package corresponding source' }
$metadata = [ordered]@{
    revision = $revision.Trim()
    repository = 'https://github.com/jmpijll/vapour'
    builtUtc = [DateTime]::UtcNow.ToString('o')
    executableSha256 = (Get-FileHash -LiteralPath (Join-Path $directory.FullName 'Vapour.exe') -Algorithm SHA256).Hash
    sourceSha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    platform = 'windows-x64'
    channel = 'unsigned-review'
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory.FullName 'build.json') -Encoding utf8
Write-Output $directory.FullName
