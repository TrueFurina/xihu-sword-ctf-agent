<#
.SYNOPSIS
  把 TOP-0 看门狗注册为 Windows 任务计划程序（开机自启、用户登录后后台运行）。
.DESCRIPTION
  创建计划任务 "Top0Watchdog"，触发器=用户登录，操作=后台运行 _watchdog_top0.ps1。
  这样每次开机/登录自动拉起看门狗，无需手动双击。
.EXAMPLE
  powershell -File scripts\_install_watchdog_task.ps1        # 安装
  powershell -File scripts\_install_watchdog_task.ps1 -Uninstall  # 卸载
#>
param([switch]$Uninstall)

$TaskName = "Top0Watchdog"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PS = Join-Path $ScriptDir "_watchdog_top0.ps1"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PS`""

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "[TOP0] 已卸载计划任务 $TaskName"
  exit 0
}

$Trigger = New-ScheduledTaskTrigger -AtLogOn
# 2026-10-21 修复：参数名是复数 DontStopIfGoingOnBatteries。
# 单数写法（DontStopIfGoingOnBattery）会让 New-ScheduledTaskSettingsSet 直接抛
# "找不到与参数名称…匹配的参数"，于是 Register-ScheduledTask 根本执行不到——
# 脚本看起来"跑过了"，任务却没注册。同批新增的 _install_snapshot_task.ps1 首次注册时
# 撞了同一个坑，才反查出来。
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "TOP-0 协同任务总账文件系统变更自动记录看门狗" -Force | Out-Null
Write-Host "[TOP0] ✅ 已注册计划任务 $TaskName（登录时后台启动）"
Write-Host "[TOP0] 验证: taskschd.msc 或 Get-ScheduledTask -TaskName $TaskName"
