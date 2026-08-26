#!/usr/bin/env bash
# ============================================================
#  Xihu Lunjian CTF-Agent - In-Race Monitor v2 (SRE 升级版)
#  Usage : bash scripts/monitor_race.sh
#  Sects :
#    S0. 进程存活（race 日志新鲜度代理）
#    S1. HTTP error counts + 频率（400/429/402）→ 降档建议
#    S2. error.category 分布（goal_log.jsonl）
#    S3. flag 对账 + 解出速率
#    S4. 健康评分汇总（5 指标 PASS/WARN/CRIT + 处置命令）
#    S5. 有效 env 快照（AppConfig 实际生效值）
#  频率窗口：状态文件 diff（data/results/monitor_state.sh），
#  两次执行间隔即窗口——频率=增量/间隔分钟×10 分钟。
# ============================================================
set -u
cd "$(dirname "$0")/.." || exit 1

RACE_LOG="data/results/race_20260821.log"
GOAL_LOG="data/results/goal_log.jsonl"
SUBMITTED="data/results/submitted_flags.json"
STATE="data/results/monitor_state.sh"
PY=".venv/Scripts/python.exe"

NOW=$(date +%s)

# ---- 状态加载（缺省首跑基线）----
LAST_TS=$NOW; LAST_429=0; LAST_402=0; LAST_400=0; LAST_SOLVED=0; LAST_DELTA=0; span=1
if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    . "$STATE" 2>/dev/null || true
fi

echo "=============================================================="
echo "[S0] 进程存活（race 日志 10min 内活跃 = 存活）"
echo "=============================================================="
ALIVE="UNKNOWN"
if [ -f "$RACE_LOG" ]; then
    MTIME=$(date -r "$RACE_LOG" +%s 2>/dev/null || echo 0)
    AGE=$(( NOW - MTIME ))
    if [ "$AGE" -le 600 ]; then ALIVE="OK"; else ALIVE="WARN"; fi
    printf "  race log 最后写入 %ss 前 | 状态: %s\n" "$AGE" "$ALIVE"
    if [ "$ALIVE" = "WARN" ]; then
        echo "  [CRIT] race 进程疑似死亡（日志 10min 无写入）→ 立即重启:"
        echo "    cd /d E:\\Program\\西湖论剑\\ctf_agent && start start_race.bat"
    fi
else
    echo "  (warn) $RACE_LOG 不存在——比赛尚未启动 start_race.bat"
fi

echo ""
echo "=============================================================="
echo "[S1] HTTP error counts + 频率（每 10min 增量）"
echo "=============================================================="
if [ -f "$RACE_LOG" ]; then
    n400=$(grep -cE "HTTP 400([^0-9]|$)" "$RACE_LOG" 2>/dev/null || true)
    n429=$(grep -cE "HTTP 429([^0-9]|$)" "$RACE_LOG" 2>/dev/null || true)
    n402=$(grep -cE "HTTP 402([^0-9]|$)" "$RACE_LOG" 2>/dev/null || true)
    printf "  HTTP 400 : %s (+%s)\n" "$n400" "$((n400 - LAST_400))"
    printf "  HTTP 402 : %s (+%s)\n" "$n402" "$((n402 - LAST_402))"
    printf "  HTTP 429 : %s (+%s)\n" "$n429" "$((n429 - LAST_429))"

    span=$(( (NOW - LAST_TS) / 60 ))
    [ "$span" -le 0 ] && span=1
    d429=$(( n429 - LAST_429 ))
    rate429=$(( d429 * 10 / span ))   # 次/10min
    printf "  频率(窗口 %.0fmin): 429=%s 次/10min\n" "$span" "$rate429"

    echo "  ── 降档建议（429 阈值）──"
    if [ "$rate429" -ge 10 ]; then
        echo "  [CRIT] 429 频率 ≥10 次/10min → 立即切 minimal(2路):"
        echo "    setx CTF_AGENT_RACE_PROFILE minimal   # 新进程生效；当前进程重启 start_race.bat"
    elif [ "$rate429" -ge 3 ]; then
        echo "  [WARN] 429 频率 3-9 次/10min → 切 medium(4路):"
        echo "    setx CTF_AGENT_RACE_PROFILE medium"
    else
        echo "  [OK]   429 频率 <3 次/10min → 维持当前档位（默认 full/6路）"
    fi
    if [ "$n402" -gt "$LAST_402" ]; then
        echo "  [CRIT] 新增 402 → deepseek 欠费！主源靠 qwen 免费额度，勿重试 deepseek:"
        echo "    setx CTF_AGENT_LLM_PROVIDER qwen"
    fi
else
    echo "  (warn) $RACE_LOG not found yet -- no race run so far"
fi

echo ""
echo "=============================================================="
echo "[S2] error.category 分布（goal_log.jsonl）"
echo "=============================================================="
if [ -f "$GOAL_LOG" ]; then
    hits=$(grep -o '"category": "[^"]*"' "$GOAL_LOG" | sort | uniq -c | sort -rn)
    if [ -n "$hits" ]; then
        echo "$hits"
    else
        echo "  (no category markers found -- no error objects yet, all good)"
    fi
    err_objs=$(grep -c '"error": {' "$GOAL_LOG" 2>/dev/null || true)
    echo "  (error objects total: $err_objs)"
else
    echo "  (warn) $GOAL_LOG not found yet"
fi

echo ""
echo "=============================================================="
echo "[S3] flag 对账 + 解出速率"
echo "=============================================================="
goal_flags="(n/a)"
if [ -f "$GOAL_LOG" ]; then
    g1=$(grep -c '"flag": "flag{' "$GOAL_LOG" 2>/dev/null || true)
    g2=$(grep -c '"flag": "DASCTF{' "$GOAL_LOG" 2>/dev/null || true)
    goal_flags=$(( g1 + g2 ))
    echo "  goal_log 非空 flags（flag{}+DASCTF{}）: $goal_flags"
else
    echo "  goal_log 非空 flags : (no file)"
fi

sub_n="(n/a)"
if [ -f "$SUBMITTED" ]; then
    if [ -x "$PY" ]; then
        sub_n=$("$PY" -c "import json,sys;print(len(json.load(open('data/results/submitted_flags.json',encoding='utf-8'))))" 2>/dev/null || echo "parse-err")
    else
        sub_n="(no venv python)"
    fi
    echo "  submitted_flags entries : $sub_n"
    if [ "$goal_flags" != "(n/a)" ] && [ "$sub_n" != "(n/a)" ] && [ "$sub_n" != "parse-err" ]; then
        delta=$(( goal_flags - sub_n ))
        ddelta=$(( delta - LAST_DELTA ))
        echo "  -> delta (goal - submitted): $delta （本窗口 +$ddelta）"
    fi
else
    echo "  submitted_flags entries : (file not found)"
fi

# 解出速率（两次 monitor 之间新解出数）
dsolved=0
if [ "$goal_flags" != "(n/a)" ] && [ "$LAST_SOLVED" -ne 0 ]; then
    dsolved=$(( goal_flags - LAST_SOLVED ))
fi
printf "  本窗口新解出: %s 题（累计 %s）\n" "$dsolved" "${goal_flags:-?}"
if [ "$span" -ge 30 ] 2>/dev/null && [ "$dsolved" -le 0 ]; then
    echo "  [WARN] 已 ${span}min 无新解出 → 可能堵在 HARD 或全题卡死，查 S2/S5 并人工介入:"
    echo "    python scripts/_emergency.py --status"
fi

echo ""
echo "=============================================================="
echo "[S4] 健康评分汇总（5 指标）"
echo "=============================================================="
score_ok=0; score_warn=0; score_crit=0
# 指标1：429 频率
if [ -f "$RACE_LOG" ]; then
    if [ "$rate429" -ge 10 ]; then echo "  1. 429 频率        : CRIT（≥10/10min）"; score_crit=$((score_crit+1));
    elif [ "$rate429" -ge 3 ]; then echo "  1. 429 频率        : WARN（3-9/10min）"; score_warn=$((score_warn+1));
    else echo "  1. 429 频率        : PASS（<3/10min）"; score_ok=$((score_ok+1)); fi
else
    echo "  1. 429 频率        : n/a（无 race log）"
fi
# 指标2：402 欠费
if [ -f "$RACE_LOG" ]; then
    if [ "$n402" -gt "$LAST_402" ]; then echo "  2. 402 欠费        : CRIT（新增 402）"; score_crit=$((score_crit+1));
    else echo "  2. 402 欠费        : PASS"; score_ok=$((score_ok+1)); fi
else
    echo "  2. 402 欠费        : n/a"
fi
# 指标3：解出速率（≥30min 无进展）
if [ "$goal_flags" != "(n/a)" ]; then
    if [ "$span" -ge 30 ] 2>/dev/null && [ "$dsolved" -le 0 ]; then echo "  3. 解出速率        : WARN（≥30min 零新解出）"; score_warn=$((score_warn+1));
    else echo "  3. 解出速率        : PASS（本窗口有新进展）"; score_ok=$((score_ok+1)); fi
else
    echo "  3. 解出速率        : n/a"
fi
# 指标4：进程存活
if [ -f "$RACE_LOG" ]; then
    if [ "$ALIVE" = "OK" ]; then echo "  4. 进程存活        : PASS（日志活跃）"; score_ok=$((score_ok+1));
    else echo "  4. 进程存活        : CRIT（日志 >10min 无写入）"; score_crit=$((score_crit+1)); fi
else
    echo "  4. 进程存活        : n/a"
fi
# 指标5：提交对账（本窗口 delta 增量 >3 = 解出 flag 未落盘 submitted_flags）
if [ "$goal_flags" != "(n/a)" ] && [ "$sub_n" != "(n/a)" ] && [ "$sub_n" != "parse-err" ]; then
    if [ "$LAST_DELTA" -gt 0 ] && [ "${ddelta:-0}" -gt 3 ]; then echo "  5. 提交对账        : WARN（delta 本窗口 +$ddelta >3，提交通道故障）"; score_warn=$((score_warn+1));
    else echo "  5. 提交对账        : PASS（落盘一致）"; score_ok=$((score_ok+1)); fi
else
    echo "  5. 提交对账        : n/a"
fi
echo "  ── 汇总: OK=$score_ok WARN=$score_warn CRIT=$score_crit ──"
if [ "$score_crit" -ge 1 ]; then
    echo "  ⚠ 有 CRIT 指标：按 [S0]/[S1]/[S3] 处置命令立即行动（先保提交/报告再重启）"
fi

echo ""
echo "=============================================================="
echo "[S5] 有效 env 快照（AppConfig 实际生效值，env+注册表回退）"
echo "=============================================================="
if [ -x "$PY" ]; then
    "$PY" -c "
from config import AppConfig, _env_or_registry
c = AppConfig.from_env()
poll_conc = _env_or_registry('CTF_AGENT_MAX_CONCURRENCY') or '2'
print(f'  provider       : {c.llm_provider}')
print(f'  light_model    : {c.light_model}')
print(f'  heavy_model    : {c.heavy_model}')
print(f'  upgrade_after  : {c.upgrade_after_attempts}')
print(f'  poller 跨题并发  : {poll_conc}  (CTF_AGENT_MAX_CONCURRENCY，赛期建议 2@full / 3@medium / 4@minimal)')
print(f'  per_q_wallclock: {c.per_question_wallclock}s  (MEDIUM/未知难度档；EASY=120 HARD=600 硬编码)')
print(f'  rate_limit/min : {c.rate_limit_per_minute}  (令牌桶；主限流实为 llm/client HTTP 信号量=4)')
print(f'  max_retries    : {c.max_retries}')
print(f'  RACE_PROFILE   : {_env_or_registry(\"CTF_AGENT_RACE_PROFILE\") or \"(未设→full/6路)\"}')
" 2>/dev/null || echo "  (config 读取失败)"
else
    echo "  (no venv python)"
fi

# ---- 状态落盘（供下次 diff）----
cat > "$STATE" <<EOF
LAST_TS=$NOW
LAST_429=${n429:-0}
LAST_402=${n402:-0}
LAST_400=${n400:-0}
LAST_SOLVED=${goal_flags:-0}
LAST_DELTA=${delta:-0}
EOF

echo ""
echo "=============================================================="
echo "[monitor done] $(date '+%F %T')"
echo "=============================================================="
