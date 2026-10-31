# Restore the kernel (config.json restore_test.repo) into a disposable folder under _caches\tmp\restore-test, run its
# gates, compare every tracked file's hash with the live tree, and append the result to logs\restore-test.jsonl.
# The scheduled task also runs this weekly (and after any failed test).
#
#   .\restore-test.ps1          # pass -> exit 0
#   .\restore-test.ps1 -Keep    # keep the disposable folder for inspection
param([switch]$Keep)
$argv = @((Join-Path $PSScriptRoot 'backup.py'), 'restore-test')
if ($Keep) { $argv += '--keep' }
& python @argv
exit $LASTEXITCODE
