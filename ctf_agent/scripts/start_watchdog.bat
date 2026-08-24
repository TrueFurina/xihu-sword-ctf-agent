@echo off
REM ============================================================
REM  TOP-0 任务总账看门狗 —— 一键启动（后台常驻）
REM  作用：任何会话改文件/commit 即自动追记到「协同任务总账-TOP0.md」
REM  用法：双击本文件，或命令行 start_watchdog.bat
REM  停止：任务管理器结束 "powershell.exe -File _watchdog_top0.ps1"
REM        或运行 stop_watchdog.bat
REM ============================================================
cd /d "E:\Program\西湖论剑\ctf_agent"

echo [TOP0] 正在后台启动看门狗...
REM 用 PowerShell 后台作业常驻，窗口最小化；-NoExit 保证 Ctrl+C 才退
start "" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Program\西湖论剑\ctf_agent\scripts\_watchdog_top0.ps1"

echo [TOP0] 看门狗已在后台启动（最小化窗口）。
echo [TOP0] 日志仅在文件变更时输出到看门狗窗口；总账变更见协同任务总账-TOP0.md 的「五、实时变更流」段。
echo [TOP0] 若要开机自启，运行: powershell -File scripts\_install_watchdog_task.ps1
timeout /t 3 >nul
