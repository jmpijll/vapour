param(
    [switch]$ListOnly,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$cases = @(
    'protection::dns_divert::tests::native_loopback_udp_tcp_passthrough_and_cleanup',
    'protection::dns_session_native_tests::native_session_filters_ipv4_udp_tcp_and_restores_direct_dns',
    'protection::dns_session_native_tests::native_session_filters_ipv6_udp_tcp_and_restores_direct_dns'
)
if ($ListOnly) {
    $cases
    return
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'These tests require Windows.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an administrator terminal while the owner is present. No elevation is requested automatically.'
    }
} finally {
    $identity.Dispose()
}
$repo = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repo 'src-tauri/Cargo.toml'
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('vapour-dns-native-' + [Guid]::NewGuid().ToString('N'))
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw 'Choose a new output directory so prior test evidence is preserved.'
}
$output = New-Item -ItemType Directory -Path $OutputDirectory
$results = [Collections.Generic.List[object]]::new()
Push-Location -LiteralPath $repo
try {
    foreach ($case in $cases) {
        $name = ($case -split '::')[-1]
        $log = Join-Path $output.FullName ($name + '.log')
        $started = [DateTime]::UtcNow
        & cargo test --color never --manifest-path $manifest --locked --lib $case -- --ignored --exact --nocapture 2>&1 |
            Tee-Object -FilePath $log
        $exitCode = $LASTEXITCODE
        $passed = $exitCode -eq 0 -and (Get-Content -LiteralPath $log -Raw) -match 'test result: ok\. 1 passed; 0 failed; 0 ignored;'
        $results.Add([ordered]@{
            test = $case
            exitCode = $exitCode
            passed = $passed
            startedUtc = $started.ToString('o')
            finishedUtc = [DateTime]::UtcNow.ToString('o')
            log = $log
        })
        ConvertTo-Json -InputObject $results.ToArray() -Depth 4 |
            Set-Content -LiteralPath (Join-Path $output.FullName 'results.json') -Encoding utf8
        if (-not $passed) {
            throw "Native DNS test failed; later tests were not started. Inspect cleanup and logs in $($output.FullName) before another run."
        }
    }
} finally {
    Pop-Location
}
Write-Output "All three DNS native cases passed. Evidence: $($output.FullName)"
