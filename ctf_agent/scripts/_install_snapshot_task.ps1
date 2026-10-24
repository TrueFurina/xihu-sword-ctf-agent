<#
.SYNOPSIS
  Register the daily data/ snapshot job into Windows Task Scheduler.

.DESCRIPTION
  Creates scheduled task "DataSnapshotDaily": every day at 22:00 local time,
  run scripts/_snapshot_data.py --skip-if-unchanged, append stdout/stderr to
  logs/snapshot_cron.log.

  Design notes (why not just "snapshot every day"):

  1. One full snapshot of data/ is ~80 MB. Snapshotting unconditionally every
     day costs tens of GB per year and fills the backup disk - the exact
     failure mode where the backup you need cannot be written. Hence
     --skip-if-unchanged: the script compares a stat fingerprint
     (file count / dir count / total bytes / newest mtime) against the newest
     existing manifest and exits early when nothing changed.

  2. -StartWhenAvailable: if the machine is off at 22:00, the run happens at
     the next boot instead of being silently skipped. A backup job that only
     works when you happen to be at the desk is not a backup job.

  3. Never deletes anything. Retention is a human decision; the script only
     warns when the snapshot count exceeds --warn-after (default 10).

  4. All paths are resolved at runtime from $MyInvocation. The repo path
     contains non-ASCII characters, and a .ps1 saved as UTF-8 without BOM is
     parsed as ANSI by Windows PowerShell 5.1 - hardcoded non-ASCII literals
     would be mangled. Therefore this file is intentionally pure ASCII.

.EXAMPLE
  powershell -File scripts\_install_snapshot_task.ps1
  powershell -File scripts\_install_snapshot_task.ps1 -Uninstall
  powershell -File scripts\_install_snapshot_task.ps1 -RunNow
  powershell -File scripts\_install_snapshot_task.ps1 -At 23:30
#>
param(
  [switch]$Uninstall,
  [switch]$RunNow,
  [string]$At = "22:00"
)

$ErrorActionPreference = "Stop"

$TaskName  = "DataSnapshotDaily"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "[snapshot] scheduled task $TaskName removed"
  exit 0
}

# --- resolve interpreter: project .venv first (same rule as setup.sh) ---
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) {
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if (-not $cmd) {
    Write-Host "[snapshot] ERROR: no python found (run 'bash setup.sh' first)"
    exit 2
  }
  $Py = $cmd.Source
}

$Entry = Join-Path $ScriptDir "_snapshot_data.py"
if (-not (Test-Path $Entry)) {
  Write-Host "[snapshot] ERROR: $Entry not found"
  exit 2
}

$LogDir = Join-Path $Root "logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$Log = Join-Path $LogDir "snapshot_cron.log"

if ($RunNow) {
  Write-Host "[snapshot] running once now (output -> $Log)"
  & $Py $Entry --skip-if-unchanged *>> $Log
  exit $LASTEXITCODE
}

# --- build action: powershell wrapper so we can append to the log file ---
# *>> redirects every stream (stdout+stderr+warning) in append mode (PS 3.0+).
$Inner  = "& '$Py' '$Entry' --skip-if-unchanged *>> '$Log'"
$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$Inner`""

$Trigger = New-ScheduledTaskTrigger -Daily -At $At

# StartWhenAvailable = catch up after a missed run; 1h cap so a hung copy
# cannot occupy the task forever.
$Settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Hours 1)

$Desc = "Daily data/ snapshot with sha256 manifest (append-only, skip when unchanged)"

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
  -Settings $Settings -Description $Desc -Force | Out-Null

Write-Host "[snapshot] OK: scheduled task '$TaskName' registered (daily at $At)"
Write-Host "[snapshot] python : $Py"
Write-Host "[snapshot] entry  : $Entry"
Write-Host "[snapshot] log    : $Log"
Write-Host "[snapshot] verify : Get-ScheduledTask -TaskName $TaskName"
Write-Host "[snapshot] manual : powershell -File scripts\_install_snapshot_task.ps1 -RunNow"
