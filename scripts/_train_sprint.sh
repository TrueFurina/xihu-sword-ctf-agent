#!/usr/bin/env bash
# =============================================================================
# 西湖论剑 CTF-Agent 赛前狂刷一键脚本（真实 LLM · 带闭环 · 零臆想参数）
#
# 背景：之前研究里臆想的 --batch-race/--priority/--preflight-check 等参数
#       全部不存在，且 _batch_solve_unified.py 是纯 mock 硬编码脚本（100%
#       解出率纯自我麻痹，用户禁刷）。本脚本全部基于真实 CLI：
#         run.py --mode cli --category <crypto|misc>   ← 真实 LLM 批量刷题
#         scripts/_preflight.py --clean                ← 赛前检查清单
#         scripts/_check_providers.py                  ← 4 provider 连通性
#         scripts/_provider_failover.py --auto         ← 自动写入可用主 provider
#         report/generator.py                          ← 解题报告
#
# 端口真相：刷题是本地 CLI，零端口。"端口连接失败"是误把 _race_start.py
#       （平台轮询器）当成 HTTP 服务访问 8080；项目唯一的 HTTP 服务是
#       run.py --mode web（FastAPI 看板，端口 8000，非 8080）。
#
# 用法：
#   bash scripts/_train_sprint.sh                 # 全流程（阶段 3 刷题耗时较长）
#   SKIP_PROBE=1 bash scripts/_train_sprint.sh    # 跳过 provider 探测（省时）
#   ONLY_STAGE=1,3 bash scripts/_train_sprint.sh  # 只跑指定阶段（逗号分隔）
#
# 阶段：0自检 → 1环境校验 → 2配置备份 → 3批量刷题 → 4归因 → 5模板缺口 → 6报告 → 7回滚
# 硬约束：不碰核心代码，只改环境变量/配置/提示词；刷题 4:3 配比（crypto15+misc10=25题）
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/.venv/Scripts/python.exe"
LOGDIR="$ROOT/logs"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG="$LOGDIR/train_sprint_${STAMP}.log"
mkdir -p "$LOGDIR"

# ── 阶段开关（默认全开）────────────────────────────────────────────
ONLY_STAGE="${ONLY_STAGE:-0,1,2,3,4,5,6,7}"
SKIP_PROBE="${SKIP_PROBE:-0}"
step() { echo ""; echo "════════════════════════════════════════════════════════"; echo "▶ 阶段 $1: $2"; echo "════════════════════════════════════════════════════════"; }
want() { case ",$ONLY_STAGE," in *",$1,"*) return 0;; *) return 1;; esac; }
note() { echo "  ─ $1"; }

# ═══════════════════ 阶段 0：自检 ═══════════════════
if want 0; then
step 0 "自检（python / 目录 / Key 存在性——只报有/无，不打印值）"
  if [ ! -f "$PY" ]; then echo "FATAL: .venv 缺失，先跑 bash setup.sh"; exit 1; fi
  echo "  ✓ python: $PY"
  for d in data/questions logs; do
    [ -d "$d" ] || mkdir -p "$d"; echo "  ✓ 目录: $d"
  done
  # Key 存在性（环境变量 or Windows 注册表，注册表探测由 config._sync 兜底）
  for k in DEEPSEEK_API_KEY QIANFAN_API_KEY DASHSCOPE_API_KEY MIMO_API_KEY ZHIPU_API_KEY; do
    if [ -n "${!k:-}" ]; then echo "  ✓ $k 已配置(env)";
    elif "$PY" -c "import os,sys;sys.path.insert(0,'.');import config;print('1' if config._env_or_registry('$k') else '0')" 2>/dev/null | grep -q 1; then
      echo "  ✓ $k 已配置(registry)"; else echo "  ✗ $k 未配置（刷题可降级其他源）"; fi
  done
  "$PY" -c "import httpx,fastapi,uvicorn" 2>/dev/null && echo "  ✓ 依赖完备(httpx/fastapi/uvicorn)" || echo "  ✗ 依赖缺失，先跑 bash setup.sh"
  echo "  → 日志: $LOG"
fi

# ═══════════════════ 阶段 1：环境校验 ═══════════════════
if want 1; then
step 1 "环境校验（preflight 检查清单 + provider 连通性）"
  note "1.1 赛前检查清单（_preflight.py --clean，清测试数据再查）"
  if [ "${SKIP_PROBE}" = "1" ]; then note "跳过 preflight（SKIP_PROBE=1）";
  else "$PY" scripts/_preflight.py --clean 2>&1 | tee -a "$LOG" | tail -25; fi
  note "1.2 主 provider 连通性（_check_providers.py：deepseek/qwen/mimo/baidu 极简探测）"
  if [ "${SKIP_PROBE}" = "1" ]; then note "跳过 provider 探测（SKIP_PROBE=1）";
  else "$PY" scripts/_check_providers.py 2>&1 | tee -a "$LOG"; fi
  note "1.3 自动写入可用主 provider（_provider_failover.py --auto）"
  if [ "${SKIP_PROBE}" = "1" ]; then note "跳过 failover 写入（SKIP_PROBE=1）";
  else "$PY" scripts/_provider_failover.py --auto 2>&1 | tee -a "$LOG" | tail -15; fi
fi

# ═══════════════════ 阶段 2：配置备份 + 刷题参数 ═══════════════════
BACKUP_FILE="$LOGDIR/env_backup_${STAMP}.sh"
if want 2; then
step 2 "配置：备份当前环境变量 → 覆盖刷题参数（仅脚本内 export，不污染注册表）"
  # 备份（供阶段 7 回滚）
  {
    echo "# 环境变量备份 ${STAMP}（阶段 7 回滚用）"
    for k in CTF_AGENT_USE_REAL_LLM CTF_AGENT_LLM_PROVIDER CTF_AGENT_LIGHT_MODEL \
             CTF_AGENT_MID_MODEL CTF_AGENT_HEAVY_MODEL CTF_AGENT_MAX_CONCURRENCY \
             CTF_AGENT_PER_Q_WALLCLOCK CTF_AGENT_UPGRADE_AFTER CTF_AGENT_MAX_RETRIES \
             CTF_AGENT_ENFORCE_WHITELIST; do
      v="${!k:-}"; echo "export $k='$v'"
    done
  } > "$BACKUP_FILE"
  echo "  ✓ 已备份 → $BACKUP_FILE"

  # 刷题硬配置（全部为 config.py from_env 真实读取的变量）
  # 主 provider 强制 deepseek（官方充值、HTTP 200、用户"使劲用"策略）；
  # 注意：_provider_failover.py --auto 会把主 provider 写成 baidu（免费源），此处必须覆盖。
  export CTF_AGENT_USE_REAL_LLM=1
  export CTF_AGENT_LLM_PROVIDER=deepseek
  export CTF_AGENT_LIGHT_MODEL=deepseek-chat
  export CTF_AGENT_MID_MODEL=qwen3.8-27b
  export CTF_AGENT_HEAVY_MODEL=deepseek-reasoner
  export CTF_AGENT_MAX_CONCURRENCY=3          # 靶机并发 ≤3（用户硬约束）
  export CTF_AGENT_PER_Q_WALLCLOCK=300        # 单题墙钟止损 300s
  export CTF_AGENT_UPGRADE_AFTER=2            # 连续 2 次失败升级重型模型
  export CTF_AGENT_MAX_RETRIES=2              # 校验循环收紧（止损）
  export CTF_AGENT_ENFORCE_WHITELIST=1        # 白名单合规闸门
  note "主 provider: ${CTF_AGENT_LLM_PROVIDER}（light=deepseek-chat / heavy=deepseek-reasoner）"
  note "并发=3 墙钟=300s 升级=2次 重试=2 白名单=开"
  echo "  关键变量已生效（仅本脚本进程）"
fi

# ═══════════════════ 阶段 3：批量刷题（真实 LLM，4:3 配比）═══════════════════
if want 3; then
step 3 "批量刷题（真实 LLM · 4:3 配比：crypto 15 + misc 10 = 25 题）"
  note "每题走 4 步闭环：跑题→归因→修复→沉淀；墙钟 300s 硬止损，超时自动跳"
  for cat in crypto misc; do
    n=$(ls data/questions/$cat/*.json 2>/dev/null | wc -l)
    echo ""
    echo "────────────── [$cat] ${n} 题（真实 LLM 求解，并发3） ──────────────"
    "$PY" run.py --mode cli --category "$cat" 2>&1 | tee -a "$LOG"
  done
  echo ""
  echo "  刷题完成，完整日志: $LOG"
fi

# ═══════════════════ 阶段 4：归因分析（A/B/C/D）═══════════════════
if want 4; then
step 4 "归因分析（从日志提取 error category → A/B/C/D 分布）"
  A=$(grep -c "stuck_loop\|空转\|no tool" "$LOG" 2>/dev/null || echo 0)
  B=$(grep -c "tool_error\|ToolExecution\|tool.*fail\|参数" "$LOG" 2>/dev/null || echo 0)
  C=$(grep -c "hallucination\|幻觉\|跨题误判" "$LOG" 2>/dev/null || echo 0)
  D=$(grep -c "wallclock_timeout\|墙钟超限\|预算超限" "$LOG" 2>/dev/null || echo 0)
  echo "  A 该用工具没用/空转 : ${A} 次"
  echo "  B 工具参数错/不会用 : ${B} 次"
  echo "  C 推理方向走偏/幻觉 : ${C} 次"
  echo "  D 超出能力边界(止损): ${D} 次"
  echo ""
  echo "  各题结果明细（✗ 未解出 → 需归因修复）："
  grep -E "^\s+\[[✓✗]\]" "$LOG" 2>/dev/null | tail -30 || true
  echo ""
  echo "  → 修复动作：A 类查 main_agent 空转强制转工具（已内置）；B 类查 tools/adapters 参数模板；"
  echo "    C 类补 skill 触发词；D 类记入比赛放弃清单（赛中直接跳过）"
fi

# ═══════════════════ 阶段 5：fast_solve 模板缺口 ═══════════════════
if want 5; then
step 5 "沉淀检查：skills/ 模板覆盖 vs 题库缺口"
  total=0; have=0
  for cat in crypto misc web reverse pwn; do
    cnt=$(ls data/questions/$cat/*.json 2>/dev/null | wc -l); [ "$cnt" = "0" ] && continue
    total=$((total+cnt))
  done
  have=$(ls skills/*.json 2>/dev/null | wc -l)
  echo "  题库题量: ${total} 道 | 已有 fast_solve 模板: ${have} 个"
  echo ""
  echo "  模板清单（skills/*.json）："
  ls skills/*.json 2>/dev/null | sed 's|skills/||; s|\.json||' | sed 's/^/    - /'
  echo ""
  echo "  → 沉淀规则：高频考点且本次刷题解出的题，若 skills/ 无对应模板 → 补一个；"
  echo "    模板结构见 skills/rsa_fermat_factor.json（trigger + steps + flag_pattern）"
fi

# ═══════════════════ 阶段 6：解题报告 ═══════════════════
if want 6; then
step 6 "生成解题报告（report/generator.py）"
  "$PY" -c "
import sys; sys.path.insert(0, '.')
from report.generator import generate_report, save_report
try:
    md = generate_report(solve_logs={})
    p = save_report(md)
    print('报告已生成:', p)
except Exception as e:
    print('报告生成跳过（需先跑过平台/刷题产生记录）:', e)
" 2>&1 | tee -a "$LOG"
fi

# ═══════════════════ 阶段 7：回滚 + 正式赛切换 ═══════════════════
if want 7; then
step 7 "配置回滚 + 正式赛模式提示"
  echo "  ── 回滚脚本内 export（恢复刷题前值）──"
  if [ -f "$BACKUP_FILE" ]; then
    for k in CTF_AGENT_USE_REAL_LLM CTF_AGENT_LLM_PROVIDER CTF_AGENT_LIGHT_MODEL \
             CTF_AGENT_MID_MODEL CTF_AGENT_HEAVY_MODEL CTF_AGENT_MAX_CONCURRENCY \
             CTF_AGENT_PER_Q_WALLCLOCK CTF_AGENT_UPGRADE_AFTER CTF_AGENT_MAX_RETRIES \
             CTF_AGENT_ENFORCE_WHITELIST; do
      unset "$k" 2>/dev/null || true
    done
    echo "  ✓ 本脚本进程内变量已还原（注册表/其他 shell 不受影响）"
    echo "  ✓ 备份文件保留: $BACKUP_FILE（如需彻底回滚：source 它）"
  fi
  echo ""
  echo "  ── 正式赛启动（今天 14:00，3h）──"
  echo "  ① 平台环境检查（需 DASCTF_BASE_URL + DASCTF_TOKEN）："
  echo "     $PY scripts/_race_start.py --probe"
  echo "  ② 一键作战（抢一血→轮询→报告）："
  echo "     $PY scripts/_race_start.py --compete"
  echo "  ③ 或看板模式（端口 8000，非 8080）："
  echo "     $PY run.py --mode web"
  echo ""
  echo "  ⚠️  赛前 30 分钟停刷：跑 $PY scripts/_preflight.py --clean 做最终自检"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "✅ 一键刷题流程结束（阶段: $ONLY_STAGE）"
echo "   日志: $LOG"
echo "════════════════════════════════════════════════════════"
