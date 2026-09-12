$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$destination=Join-Path $repository 'src-tauri/vendor/windivert'
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('vapour-windivert-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
 $archive=Join-Path $temporary 'WinDivert.zip'
 Invoke-WebRequest -Uri 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $archive
 if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'){throw 'WinDivert archive checksum mismatch'}
 Expand-Archive -LiteralPath $archive -DestinationPath $temporary
 $source=Join-Path $temporary 'WinDivert-2.2.2-A/x64'
 $expected=@{'WinDivert.dll'='C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2';'WinDivert64.sys'='8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2'}
 foreach($name in $expected.Keys){if((Get-FileHash -LiteralPath (Join-Path $source $name) -Algorithm SHA256).Hash -ne $expected[$name]){throw "WinDivert checksum mismatch: $name"}}
 New-Item -ItemType Directory -Force -Path $destination | Out-Null
 foreach($name in $expected.Keys){Copy-Item -LiteralPath (Join-Path $source $name) -Destination (Join-Path $destination $name)}
 Write-Host 'Verified WinDivert x64 runtime staged. No driver was loaded.'
} finally {
 $resolved=[IO.Path]::GetFullPath($temporary)
 $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
 if(-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected cleanup location'}
 if([IO.Path]::GetFileName($resolved) -notlike 'vapour-windivert-*'){throw 'Unexpected cleanup directory'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
