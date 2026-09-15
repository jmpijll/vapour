param(
    [Parameter(Mandatory=$true)][int]$ProcessId,
    [ValidateRange(2,3600)][int]$Seconds = 30
)
$ErrorActionPreference = 'Stop'
$rootProcess = Get-Process -Id $ProcessId
if ($null -eq $rootProcess.StartTime -or $null -eq $rootProcess.CPU) { throw 'Cannot read target metrics. Run the profiler at the same privilege level as the app.' }
$rootStarted = $rootProcess.StartTime.ToUniversalTime().Ticks
$known = @{}
$samples = [System.Collections.Generic.List[object]]::new()
$watch = [Diagnostics.Stopwatch]::StartNew()
$cpuDelta = 0.0
while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
    $currentRoot = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (!$currentRoot -or $currentRoot.StartTime.ToUniversalTime().Ticks -ne $rootStarted) { throw 'Target process exited or its PID was reused.' }
    $rows = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId)
    $ids = [System.Collections.Generic.HashSet[int]]::new()
    [void]$ids.Add($ProcessId)
    do {
        $changed = $false
        foreach ($row in $rows) {
            if ($ids.Contains([int]$row.ParentProcessId) -and $ids.Add([int]$row.ProcessId)) { $changed = $true }
        }
    } while ($changed)
    $privateBytes = 0L; $workingSet = 0L; $count = 0
    foreach ($taskId in $ids) {
        $taskProcess = Get-Process -Id $taskId -ErrorAction SilentlyContinue
        if (!$taskProcess) { continue }
        try {
            if ($null -eq $taskProcess.StartTime -or $null -eq $taskProcess.CPU) { throw 'Process metrics unavailable' }
            $identity = '{0}:{1}' -f $taskId,$taskProcess.StartTime.ToUniversalTime().Ticks
            $cpu = [double]$taskProcess.CPU
            if ($known.ContainsKey($identity)) { $cpuDelta += [Math]::Max(0,$cpu-$known[$identity]) }
            $known[$identity] = $cpu
            $privateBytes += $taskProcess.PrivateMemorySize64
            $workingSet += $taskProcess.WorkingSet64
            $count++
        } catch { continue }
    }
    $samples.Add([pscustomobject]@{Seconds=[Math]::Round($watch.Elapsed.TotalSeconds,3);Processes=$count;PrivateBytes=$privateBytes;WorkingSetBytes=$workingSet})
    Start-Sleep -Milliseconds 1000
}
$elapsed = $watch.Elapsed.TotalSeconds
[pscustomobject]@{
    DurationSeconds=[Math]::Round($elapsed,3)
    ObservedCpuSeconds=[Math]::Round($cpuDelta,4)
    PercentOfOneLogicalCpu=[Math]::Round(100*$cpuDelta/$elapsed,3)
    PeakPrivateBytes=($samples | Measure-Object PrivateBytes -Maximum).Maximum
    PeakSummedWorkingSetBytes=($samples | Measure-Object WorkingSetBytes -Maximum).Maximum
    Samples=$samples
    Limitations='Polling misses processes that start and exit between samples and CPU before first observation. Summed working sets may double-count shared pages. Run under a documented workload; this is not an accuracy or packet-loss test.'
} | ConvertTo-Json -Depth 4
