@echo off
rem ============================================================
rem  Xihu Lunjian CTF-Agent - Web Dashboard Starter (P0-1)
rem  Entry  : run.py --mode web (port 8000)
rem  Log    : data\results\web_20260821.log
rem  Env    : baidu qianfan real LLM + whitelist enforced
rem ============================================================
set CTF_AGENT_USE_REAL_LLM=1
rem 2026-08-21 赛后修复：deepseek 402 已死，默认源切 baidu 千帆（免费+实测200 OK）
set CTF_AGENT_LLM_PROVIDER=baidu
rem LIGHT/HEAVY 跟随 provider 默认（ernie-3.5-8k-preview），防模型/端点不匹配 404
set CTF_AGENT_LIGHT_MODEL=
set CTF_AGENT_HEAVY_MODEL=
set CTF_AGENT_ENFORCE_WHITELIST=1

cd /d "%~dp0"

set PY=.venv\Scripts\python.exe
if not exist "%PY%" (
    echo [ERROR] venv python not found: %PY%
    exit /b 1
)

if not exist "data\results" mkdir "data\results"

echo [%date% %time%] Starting web dashboard: run.py --mode web (port 8000)
"%PY%" run.py --mode web > data\results\web_20260821.log 2>&1
set EXIT_CODE=%ERRORLEVEL%
echo [%date% %time%] Web process exited with code %EXIT_CODE% (see data\results\web_20260821.log)
exit /b %EXIT_CODE%
