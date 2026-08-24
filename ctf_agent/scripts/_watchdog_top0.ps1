<#
.SYNOPSIS
  TOP-0 协同任务总账 —— 文件系统变更自动记录看门狗（手动审计工具，非默认）

.DESCRIPTION
  【2026-08-22 决策】本项目不设开机自启、不常驻任何进程（过几天不做项目
  不能留后台任务卡电脑）。默认破黑盒机制 = 共识登记（scripts/_log_task.py
  一键登记）+ git hook 机器兜底（git_hooks/post-commit|post-merge）。

  本脚本仅作为**手动深度审计工具**保留：当你怀疑"某个会话改了文件但既没
  commit 也没登记"时，手动跑一次监听某段时间，捕获 scripts/tools/skills/
  core/ctfplatform/tests/AGENTS.md 的写入，追记到总账「五、实时变更流」段。
  弥补 git hook 只覆盖 commit、拦不住「改文件不提交」的盲区。

  特点：
  - 防抖 1.5s：同一次保存的多文件事件合并为一行
  - 跳过 .git / .venv / __pycache__ / node_modules / *.pyc
  - 会话识别：读环境变量 CT_AGENT_SESSION，缺省记 "manual/<user>"

.PARAMETER Once
  只跑一次自检（验证总账可写 + 监听可起），不常驻。用于诊断。

.EXAMPLE
  .\scripts\_watchdog_top0.ps1 -Once      # 自检
  # 手动审计（需 Ctrl+C 停止，用完即退）：
  .\scripts\_watchdog_top0.ps1
#>

param([switch]$Once)

$ErrorActionPreference = "Continue"
$RepoRoot = "E:\Program\西湖论剑\ctf_agent"
$Top0     = "E:\Program\西湖论剑\协同任务总账-TOP0.md"
$WatchDirs = @("scripts","tools","skills","core","ctfplatform","tests","AGENTS.md")
$Exclude  = @(".git",".venv","__pycache__","node_modules",".pytest_cache")
$DebounceMs = 1500

function Write-Top0Row {
  param([string]$Session, [string]$Action, [string]$Files)
  if (-not (Test-Path $Top0)) { Write-Warning "[TOP0] 总账不存在: $Top0"; return }
  $when = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = "| $when | $Session | $Action | $Files |"
  # 确保「五、实时变更流」段存在
  if (-not (Select-String -Quiet -Pattern "## 五、实时变更流（自动记录）" -Path $Top0)) {
    Add-Content -Path $Top0 -Value ""
    Add-Content -Path $Top0 -Value "## 五、实时变更流（自动记录）"
    Add-Content -Path $Top0 -Value ""
    Add-Content -Path $Top0 -Value "> 本段由 git post-commit/post-merge hook + _watchdog_top0.ps1 看门狗自动追记，任何会话 commit 或手动改文件即落账，用于打破多智能体黑盒。人工勿手改本段（除非补登非 commit 改动）。"
    Add-Content -Path $Top0 -Value ""
    Add-Content -Path $Top0 -Value "| 时间 | 会话 | 动作 | 改动文件 |"
    Add-Content -Path $Top0 -Value "|---|---|---|---|"
  }
  # 插入到表头分隔行之后（倒序：新在上）
  $content = Get-Content -Path $Top0
  $out = @()
  $inserted = $false
  for ($i=0; $i -lt $content.Count; $i++) {
    $out += $content[$i]
    if (-not $inserted -and $content[$i] -match "^\|---+\|---+\|---+\|---+\|") {
      $out += $line
      $inserted = $true
    }
  }
  if (-not $inserted) { $out += $line }
  Set-Content -Path $Top0 -Value $out -Encoding UTF8
  Write-Host "[TOP0] ✅ 已记录 $Action : $Files" -ForegroundColor Green
}

function Get-Session {
  $s = $env:CT_AGENT_SESSION
  if ([string]::IsNullOrWhiteSpace($s)) { $s = "manual/$($env:USERNAME)" }
  return $s
}

# 自检模式
if ($Once) {
  Write-Host "[TOP0] 自检：总账=$(Test-Path $Top0) 仓库=$RepoRoot"
  Write-Top0Row -Session (Get-Session) -Action "WATCHDOG_SELFTEST" -Files "（自检，验证可写）"
  Write-Host "[TOP0] 自检完成"
  exit 0
}

Write-Host "[TOP0] 看门狗启动，监控: $($WatchDirs -join ', ')" -ForegroundColor Cyan
Write-Host "[TOP0] 会话标识: $(Get-Session) | 防抖 ${DebounceMs}ms | Ctrl+C 退出" -ForegroundColor Cyan

$watchers = @()
foreach ($d in $WatchDirs) {
  $full = Join-Path $RepoRoot $d
  if (-not (Test-Path $full)) { Write-Host "[TOP0] 跳过不存在: $full" -ForegroundColor Yellow; continue }
  $attr = [System.IO.NotifyFilters]::LastWrite -bor [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::DirectoryName
  $w = New-Object System.IO.FileSystemWatcher($full, "*.*")
  $w.NotifyFilter = $attr
  $w.IncludeSubdirectories = $true
  $w.EnableRaisingEvents = $true
  $watchers += $w
}

# 事件聚合（防抖）
$buffer = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$lastFlush = [datetime]::MinValue

$action = {
  param($sender, $e)
  $name = $e.Name
  $full = $e.FullPath
  # 排除项
  foreach ($ex in $Exclude) { if ($full -like "*\$ex\*" -or $name -like "*$ex*") { return } }
  if ($name -like "*.pyc") { return }
  $kind = switch ($e.ChangeType) {
    'Created' { '+' }; 'Changed' { '~' }; 'Deleted' { '-' }; 'Renamed' { '>' }; default { '?' }
  }
  $buffer.Enqueue("$kind $name")
}

foreach ($w in $watchers) {
  Register-ObjectEvent -InputObject $w -EventName Changed -Action $action | Out-Null
  Register-ObjectEvent -InputObject $w -EventName Created -Action $action | Out-Null
  Register-ObjectEvent -InputObject $w -EventName Deleted -Action $action | Out-Null
  Register-ObjectEvent -InputObject $w -EventName Renamed -Action $action | Out-Null
}

try {
  while ($true) {
    Start-Sleep -Milliseconds 500
    $now = Get-Date
    if ($buffer.Count -gt 0 -and ($now - $lastFlush).TotalMilliseconds -ge $DebounceMs) {
      $files = @()
      while ($buffer.TryDequeue([ref]$tmp)) { $files += $tmp }
      $uniq = ($files | Select-Object -Unique | Select-Object -First 15) -join " "
      if ($files.Count -gt 15) { $uniq += " …(+$($files.Count - 15))" }
      Write-Top0Row -Session (Get-Session) -Action "FS_CHANGE($($files.Count))" -Files $uniq
      $lastFlush = $now
    }
  }
} finally {
  foreach ($w in $watchers) { $w.Dispose() }
  Write-Host "[TOP0] 看门狗已停止" -ForegroundColor Yellow
}
