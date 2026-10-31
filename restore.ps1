# Restore a repo from its protected mirror plus the latest (or a named) snapshot into a FRESH folder, list the belt
# units to replay, and rerun the repo's gates. See README.md.
#
#   .\restore.ps1 kernel                          # -> E:\AI Programs\_restore\kernel-<stamp>
#   .\restore.ps1 kernel -Snapshot 2026-10-31-0130 -Dest D:\tmp\kernel
#   .\restore.ps1 kernel -InPlace                 # restore, then (after you type the repo name) swap it in for the live folder
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Repo,
    [string]$Snapshot,
    [string]$Dest,
    [switch]$NoGates,
    [switch]$InPlace
)
$ErrorActionPreference = 'Stop'
$py = Join-Path $PSScriptRoot 'backup.py'
$argv = @($py, 'restore', $Repo)
if ($Snapshot) { $argv += @('--snapshot', $Snapshot) }
if ($Dest) { $argv += @('--dest', $Dest) }
if ($NoGates) { $argv += '--no-gates' }
$json = & python @argv
$code = $LASTEXITCODE
$json
if (-not $InPlace) { exit $code }

$rep = ($json -join "`n") | ConvertFrom-Json
if ($code -ne 0) { Write-Host "Gates failed: not swapping the restore in. It stays at $($rep.dest)."; exit $code }
$cfg = Get-Content (Join-Path $PSScriptRoot 'config.json') -Raw | ConvertFrom-Json
$live = $cfg.repos.$Repo
if (-not $live) { Write-Host "In-place restore is only for the platform repos in config.json."; exit 2 }
$answer = Read-Host "Replace the live folder $live with $($rep.dest)? The live folder is renamed aside, not deleted. Type '$Repo' to confirm"
if ($answer -ne $Repo) { Write-Host 'Not confirmed; nothing changed.'; exit 1 }
$aside = "$live.before-restore-$(Get-Date -Format yyyyMMdd-HHmmss)"
if (Test-Path $live) { Rename-Item -LiteralPath $live -NewName (Split-Path $aside -Leaf) }
Move-Item -LiteralPath $rep.dest -Destination $live
Write-Host "Restored $Repo in place. The previous folder is at $aside (node_modules there may hold links: never delete it with a recursive remove)."
