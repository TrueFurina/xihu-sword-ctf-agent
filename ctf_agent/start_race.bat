@echo off
rem ============================================================
rem  Xihu Lunjian CTF-Agent - Race Starter (P0-1)
rem  Entry  : scripts\_race_start.py --compete
rem  Log    : data\results\race.log (append)
rem  Env    : glm-4-flash (Z.ai 永久免费, ZHIPU_API_KEY) primary + baidu/xfyun 多源 + whitelist
rem  Note   : platform token from CTF_AGENT_PLATFORM_TOKEN /
rem           DASCTF_TOKEN env or Windows registry (setx)
rem ============================================================
set CTF_AGENT_USE_REAL_LLM=1
rem 2026-08-21 赛后修复：provider 从 deepseek 改 baidu（deepseek 402 已死）。
rem 竞速矩阵实际由 _race_start.py RACE_PROFILES 按 RACE_PROFILE 构建，
rem 此处 provider 仅影响单源兜底路径。2026-11-08 默认改 glm：glm-4-flash 为
rem Z.ai 永久免费档（$0），ZHIPU_API_KEY 已确认有效并真发通（preflight ⑤ PASS），
rem 不再依赖 ernie 余额。baidu 仍保留在 live/medium/minimal 矩阵中作多源。
set CTF_AGENT_LLM_PROVIDER=glm
rem 防御：显式清空 base_url，避免继承 WorkBuddy Bash 环境里遗留的
rem CTF_AGENT_LLM_BASE_URL=https://qianfan.baidubce.com/...（8/19 旧配置），
rem 否则该值会覆盖每个 provider 的正确端点 → 全 401（LLM 失效根因）。
set CTF_AGENT_LLM_BASE_URL=
rem LIGHT/HEAVY 跟随 provider 默认（ernie-3.5-8k-preview）——显式设 deepseek-chat
rem 会模型/端点不匹配 404（16:48 灾难同款根因），故清空。
set CTF_AGENT_LIGHT_MODEL=
set CTF_AGENT_HEAVY_MODEL=
set CTF_AGENT_ENFORCE_WHITELIST=1
rem 竞速：live(多源，靠熔断剔除死源)；'谁能用'查 scripts\_llm_pool_status.py 快照，勿手写"实测存活"
set CTF_AGENT_RACE_PROFILE=live
rem LLM 矩阵墙钟 150s（数学引擎未命中后快速换题，抢吞吐）
set CTF_AGENT_RACE_WALLCLOCK=150
rem 放题高频窗口 3s 轮询 180s（抢一血）
set CTF_AGENT_MAX_CONCURRENCY=3

cd /d "%~dp0"

set PY=.venv\Scripts\python.exe
if not exist "%PY%" (
    echo [ERROR] venv python not found: %PY%
    exit /b 1
)

if not exist "data\results" mkdir "data\results"

echo [%date% %time%] Starting race mode: scripts\_race_start.py --compete
"%PY%" scripts\_race_start.py --compete >> data\results\race.log 2>&1
set EXIT_CODE=%ERRORLEVEL%
echo [%date% %time%] Race process exited with code %EXIT_CODE% (see data\results\race.log)
exit /b %EXIT_CODE%
