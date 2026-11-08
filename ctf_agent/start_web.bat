@echo off
rem ============================================================
rem  Xihu Lunjian CTF-Agent - Web Dashboard Starter (P0-1)
rem  Entry  : run.py --mode web (port 8000)
rem  Log    : data\results\web.log (append)
rem  Env    : glm-4-flash (Z.ai 永久免费, ZHIPU_API_KEY) primary + whitelist enforced
rem ============================================================
set CTF_AGENT_USE_REAL_LLM=1
rem 2026-08-21 赛后修复：deepseek 402 已死，默认源切 baidu 千帆（免费+实测200 OK）。
rem 2026-11-08 默认改 glm：glm-4-flash 为 Z.ai 永久免费档（$0），ZHIPU_API_KEY 已
rem 确认有效并真发通（preflight ⑤ PASS）。Web 面板直接走 CTF_AGENT_LLM_PROVIDER，
rem 故此处改 glm 即让 8000 面板免费用上已验证可用源。
set CTF_AGENT_LLM_PROVIDER=glm
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
"%PY%" run.py --mode web >> data\results\web.log 2>&1
set EXIT_CODE=%ERRORLEVEL%
echo [%date% %time%] Web process exited with code %EXIT_CODE% (see data\results\web.log)
exit /b %EXIT_CODE%
