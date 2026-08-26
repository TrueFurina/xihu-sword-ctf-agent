#!/usr/bin/env bash
# 西湖论剑 CTF-Agent 赛前一键环境就绪（2026-08-21 锐评整改产物）
#
# 用法：bash setup.sh            # 建 venv + 依赖 + 白名单预检 + 全测试
#       bash setup.sh --e2e      # 追加端到端平台验证（B-04：题面/附件/靶机三件套）
#                                # ⚠️ 决赛前 1h 必跑；改完平台解析代码后必跑
# 作用：在项目内建独立 .venv，装全套依赖，跑 preflight + 全测试
#
# ⚠️ 赛中启动解释器必须是 .venv/Scripts/python.exe，不能用 managed python
#    （managed python 无 httpx，LLM 路径全失效）

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PY="${ROOT}/.venv/Scripts/python.exe"
PIP="${ROOT}/.venv/Scripts/pip.exe"

# ── 参数解析：--e2e 追加端到端平台验证（2026-08-21 B-04）──
E2E=0
for _arg in "$@"; do
    [ "$_arg" = "--e2e" ] && E2E=1
done

# 1. 建 venv（若不存在）
if [ ! -f "$PY" ]; then
    echo "[1/4] 建立项目内 .venv..."
    "C:/Users/Lenovo/.workbuddy/binaries/python/versions/3.13.12/python.exe" -m venv .venv
else
    echo "[1/4] .venv 已存在"
fi

# 2. 装依赖
echo "[2/4] 安装依赖（httpx/aiohttp/fastapi/uvicorn/pytest/gmpy2/pycryptodome）..."
"$PIP" install "httpx>=0.27,<0.29" "aiohttp>=3.9" "fastapi>=0.110,<0.116" "uvicorn>=0.29" "pytest>=8.0" "gmpy2>=2.1" "pycryptodome>=3.20" >/dev/null

# 3. 白名单预检
echo "[3/4] 白名单合规预检..."
"$PY" scripts/_preflight_whitelist.py

# 3.5 网络三查（锐评 C1：宿主环境着火是初赛漏诊的第三层根因）
#     诊断模式（非 --strict）：只报告不阻断——赛后平台常关、代理常死，
#     开战前真正的闸门在 _race_start.py --compete 的 e2e 预检（A3）。
echo "[3.5/5] 网络三查（代理存活 / LLM 端点直连 / 平台直连）..."
"$PY" scripts/_net_check.py || echo "  ⚠️ 网络三查发现不可达端点（诊断模式不阻断；开战前请处理或 --strict）"

# 4. 全测试（真门禁，锐评 A2：旧循环逐文件裸跑，27 个文件仅 9 个有 __main__，
#    其余永远打印 OK——假门禁。现改为单次 pytest 真跑，失败即 exit 1 阻断开赛。）
echo "[4/5] 全测试套件（pytest -m \"not slow\"，失败即阻断）..."
if ! "$PY" -m pytest tests/ -q -m "not slow"; then
    echo ""
    echo "❌ 测试门禁未通过——禁止开赛。修复上述失败后重跑 bash setup.sh"
    exit 1
fi

# 5. 端到端平台验证（--e2e 指定时执行；B-04 2026-08-21 接入）
if [ "$E2E" = "1" ]; then
    echo "[5/5] 端到端平台验证（题面/附件/靶机三件套）..."
    "$PY" scripts/_e2e_verify.py
else
    echo "[5/5] 跳过端到端平台验证（决赛前 1h / 改码后必跑：bash setup.sh --e2e）"
fi

# ── 安装 git hooks（自动记录机制，破多智能体黑盒）────────
# 用 core.hooksPath 指向仓库内 git_hooks/，使 hook 随仓库走、clone 即生效，
# 无需手动复制到 .git/hooks/（解决「hook 不进 git、换机器要手动装」隐患）。
# post-commit/post-merge 会在每次 commit/merge 时自动把记录追记到 TOP-0 总账。
echo "[*] 安装 git hooks（core.hooksPath=git_hooks）..."
git config core.hooksPath git_hooks
git config core.fileMode false
echo "  ✅ hooks 已指向 git_hooks/（post-commit/post-merge 自动记总账）"
# pre-commit 双门禁：scripts/hooks/ 为源、git_hooks/ 为激活位（hooksPath 只认 git_hooks/）。
# 守卫式同步——git_hooks/pre-commit 已存在则不覆盖（防旧源滞后覆盖已部署版）。
if [ -f scripts/hooks/pre-commit ] && [ ! -f git_hooks/pre-commit ]; then
    cp scripts/hooks/pre-commit git_hooks/pre-commit
    chmod +x git_hooks/pre-commit
    echo "  ✅ pre-commit 门禁已从 scripts/hooks 部署到 git_hooks/"
fi
# commit-msg 门禁（2026-08-23：commit message 假水位拦截——$1=message 路径）。
# 同样守卫式同步；缺失 = 99fb169 类"message 写假水位"无拦截。
if [ -f scripts/hooks/commit-msg ] && [ ! -f git_hooks/commit-msg ]; then
    cp scripts/hooks/commit-msg git_hooks/commit-msg
    chmod +x git_hooks/commit-msg
    echo "  ✅ commit-msg 门禁已从 scripts/hooks 部署到 git_hooks/"
fi

echo ""
echo "=== 赛前就绪 ==="
echo "赛中启动（2026-08-21 勘误：run.py 无 --race/--web 参数）："
echo "  作战：$PY scripts/_race_start.py --compete"
echo "  探测：$PY scripts/_race_start.py --probe"
echo "  看板：$PY run.py --mode web"
echo "  e2e：$PY scripts/_e2e_verify.py   # 决赛前 1h / 改平台解析代码后必跑"
echo ""

# ── 关键环境变量：真实固化（2026-08-21 P0 整改）────────────
# 之前此处只是 echo 提示，并未真正 export，新 shell 跑 run.py 拿不到正确值。
# 现改为：① 本 shell 内 export（source setup.sh 时立即生效）；
#         ② setx 写入 Windows 注册表（HKCU\Environment），
#            config.py / _preflight_whitelist.py 导入时自动同步注册表→os.environ，
#            确保"新开 shell 直接跑 run.py"也能拿到正确值（跨 shell 持久）。
echo "关键环境变量（固化到注册表 + 本 shell export）："
# ⚠️ 2026-08-21 赛后修复：默认 provider 从 deepseek 改为 baidu 千帆！
# deepseek 正式赛 402 余额耗尽（Insufficient Balance），实测 5 死源之一。
# baidu ernie-3.5-8k-preview 永久免费 + 实测 200 OK（2.6s），为全系统最强单源。
# LIGHT/HEAVY_MODEL 不显式设置 → 跟随 provider 默认模型（ernie-3.5-8k-preview），
# 避免"模型与端点不匹配"（如 deepseek-chat 打到千帆端点 404）——16:48 灾难同款根因。
export CTF_AGENT_USE_REAL_LLM=1
export CTF_AGENT_LLM_PROVIDER=baidu
unset CTF_AGENT_LIGHT_MODEL 2>/dev/null || true
unset CTF_AGENT_HEAVY_MODEL 2>/dev/null || true
export CTF_AGENT_ENFORCE_WHITELIST=1
export CTF_AGENT_RACE_PROFILE=ultra
export CTF_AGENT_RACE_WALLCLOCK=300
export CTF_AGENT_MAX_CONCURRENCY=4
# 持久化到注册表（setx 不可用时静默跳过，不影响本 shell）
if command -v setx >/dev/null 2>&1; then
    setx CTF_AGENT_USE_REAL_LLM 1 >/dev/null 2>&1 || true
    setx CTF_AGENT_LLM_PROVIDER baidu >/dev/null 2>&1 || true
    setx CTF_AGENT_LIGHT_MODEL "" >/dev/null 2>&1 || true
    setx CTF_AGENT_HEAVY_MODEL "" >/dev/null 2>&1 || true
    setx CTF_AGENT_ENFORCE_WHITELIST 1 >/dev/null 2>&1 || true
    setx CTF_AGENT_RACE_PROFILE ultra >/dev/null 2>&1 || true
    setx CTF_AGENT_RACE_WALLCLOCK 300 >/dev/null 2>&1 || true
    setx CTF_AGENT_MAX_CONCURRENCY 4 >/dev/null 2>&1 || true
fi
# ── 全模型矩阵 API Key 校验（2026-08-21 安全审计后脱敏）────────
# 全部 key 已固化到 HKCU\Environment（注册表），此处不再写明文（防 git 泄露）。
# off-whitelist 的 (GROK/TOKENROUTER/OPENROUTER/PEEZY/MODELSCOPE) 仅存环境变量，
# 绝不进比赛路由（不在西湖论剑白名单，路由会被 client._check_whitelist fail-closed 拦截）。
# 换机/重装后恢复：按下方向量逐项 setx 即可（原 scripts/_restore_env_keys.py 已随
# 赛后脚本归档清理移除，恢复方式以本清单为准——setx 写入 HKCU\Environment 后新进程生效）。
_CTF_KEY_VARS="TOKENHUB_API_KEY ARK_API_KEY MOONSHOT_API_KEY SILICONFLOW_API_KEY \
SENSENOVA_API_KEY ZHIPU_API_KEY ZHIPU_API_KEY_2 XFYUN_API_KEY XFYUN_SPARK_X2_FLASH_KEY \
XFYUN_SPARK_X_BATCH_KEY XFYUN_SPARK_PRO_KEY GROK_API_KEY TOKENROUTER_API_KEY \
OPENROUTER_API_KEY PEEZY_API_KEY MODELSCOPE_API_KEY"
if command -v reg >/dev/null 2>&1; then
    for _v in $_CTF_KEY_VARS; do
        if ! reg query "HKCU\\Environment" //v "$_v" >/dev/null 2>&1; then
            echo "  [warn] $_v 未在注册表——请手动恢复: setx $_v <key>"
        fi
    done
fi
echo "  CTF_AGENT_USE_REAL_LLM=1"
echo "  CTF_AGENT_LLM_PROVIDER=baidu   # 单 LLM 安全默认(ernie-3.5 免费)；deepseek 等已在 ultra 矩阵内"
echo "  CTF_AGENT_LIGHT_MODEL=<跟随默认 ernie-3.5-8k-preview>"
echo "  CTF_AGENT_HEAVY_MODEL=<跟随 light>"
echo "  CTF_AGENT_ENFORCE_WHITELIST=1"
echo "  CTF_AGENT_RACE_PROFILE=ultra   # 11路实测存活矩阵(百炼qwen-plus+千帆+智谱+讯飞+TokenHub+豆包+Kimi+MiMo)"
echo "  CTF_AGENT_RACE_WALLCLOCK=300"
echo "  CTF_AGENT_MAX_CONCURRENCY=4"
echo "  TOKENHUB/ARK/MOONSHOT/SILICONFLOW/SENSENOVA/ZHIPU/DEEPSEEK/DASHSCOPE/QIANFAN/MIMO/XFYUN_API_KEY=<已固化>"
echo "  GROK/TOKENROUTER/OPENROUTER/PEEZY/MODELSCOPE=<仅存环境变量，off-白名单不进比赛路由>"
