# Install (or update) the backup job: copy backup.py and config.json to <root>\bin, deny writes and deletes on that
# copy so an agent editing Toolchain\backup cannot change what the scheduled task runs, and register the 30-minute
# task "RealitySim\Backup" for the current user (no admin needed: it runs only while Rex is logged on).
# Run by a keeper or Rex, never from a belt unit.
#
#   .\install.ps1              # copy + register
#   .\install.ps1 -CopyOnly    # refresh the protected copy after changing backup.py
param([switch]$CopyOnly)
$ErrorActionPreference = 'Stop'
$cfg = Get-Content (Join-Path $PSScriptRoot 'config.json') -Raw | ConvertFrom-Json
$root = $cfg.root -replace '/', '\'
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
icacls $bin /remove:d '*S-1-1-0' /T /C /Q | Out-Null
foreach ($f in 'backup.py', 'config.json') { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination $bin -Force }
icacls $bin /deny '*S-1-1-0:(DE,DC)' /C /Q | Out-Null
foreach ($f in 'backup.py', 'config.json') { icacls (Join-Path $bin $f) /deny '*S-1-1-0:(WD,AD,WEA,WA,DE)' /C /Q | Out-Null }
Write-Host "Protected copy written to $bin"
if ($CopyOnly) { exit 0 }

$pyw = (Get-Command pythonw.exe).Source
$action = New-ScheduledTaskAction -Execute $pyw -Argument "`"$bin\backup.py`" run" -WorkingDirectory $bin
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 30)
# -Priority 4 (normal): the default 7 runs the job as a background process with low I/O, and under a busy belt each
# git call took ~20 s, so one run outlasted the next two (BKP-17).
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -Priority 4 `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskPath '\RealitySim\' -TaskName 'Backup' -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Reality-sim backup (Toolchain/backup): mirror every repo, dated protected snapshot, prune, weekly restore test.' -Force | Out-Null
Get-ScheduledTask -TaskPath '\RealitySim\' -TaskName 'Backup' | Select-Object TaskName, State
