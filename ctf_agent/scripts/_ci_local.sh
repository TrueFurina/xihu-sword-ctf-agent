#!/usr/bin/env bash
# 本地 CI 等价入口（2026-10-21）
#
# 为什么需要：`.github/workflows/ci.yml` 跑的三道闸门（静态 / 测试 / 覆盖率）
# 只有在 push 之后才知道红不红。而本项目的实际工作方式是「本地车道分支 +
# 合并闸门」，等到 push 才发现红，等于把反馈延迟到最不该延迟的时刻。
# 本脚本在本地按**完全相同的顺序与参数**跑一遍，让"本地绿 = CI 绿"成立。
#
# 与 CI 的唯一差别：CI 用干净虚拟机重新装依赖，本脚本复用现有 .venv。
# 所以本脚本绿只证明**代码**没问题，不证明依赖声明完整——后者只有在 CI
# 或 `bash setup.sh` 重建环境的路径上才能验。
#
# 用法：
#   bash scripts/_ci_local.sh            # 三道闸门全跑
#   bash scripts/_ci_local.sh --fast     # 跳过覆盖率（约省 3 分钟，只验静态+测试）
#   bash scripts/_ci_local.sh --static   # 只跑静态门禁（改完代码存盘即跑，秒级）
#
# 退出码：0 全过 / 1 有闸门失败 / 2 环境不可用

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── 定位解释器：优先项目 .venv（与 setup.sh / 赛中启动一致）──
if [ -x ".venv/Scripts/python.exe" ]; then
    PY=".venv/Scripts/python.exe"
elif [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
    echo "⚠️  未找到 .venv，回退到系统 python3（依赖可能不全，参考 bash setup.sh）"
else
    echo "❌ 找不到可用 python（先跑 bash setup.sh）"
    exit 2
fi

FAST=0
ONLY_STATIC=0
for _a in "$@"; do
    case "$_a" in
        --fast) FAST=1 ;;
        --static) ONLY_STATIC=1 ;;
    esac
done

FAILED=0
FAILED_NAMES=""

mark_fail() { FAILED=1; FAILED_NAMES="$FAILED_NAMES $1"; }

# ── 闸门 1：静态（秒级，永远是第一道）──
echo ""
echo "════ [1/3] 静态门禁（ruff，分级零容忍）════"
if ! "$PY" scripts/_gate_static.py; then
    mark_fail "static"
fi

if [ "$ONLY_STATIC" = "1" ]; then
    echo ""
    echo "（--static：只跑静态门禁）"
    [ "$FAILED" = "0" ] && { echo "✅ 静态门禁通过"; exit 0; } || { echo "❌ 静态门禁失败:$FAILED_NAMES"; exit 1; }
fi

# ── 闸门 2+3：测试 + 覆盖率（同一次跑，与 CI 一致）──
echo ""
if [ "$FAST" = "1" ]; then
    echo "════ [2/3] 测试门禁（--fast：不采覆盖率）════"
    if ! "$PY" -m pytest -q -m "not slow and not local" --timeout=120 -p no:cacheprovider; then
        mark_fail "tests"
    fi
    echo ""
    echo "（--fast：跳过覆盖率闸门）"
else
    echo "════ [2/3] 测试门禁 + 覆盖率采集（约 7 分钟）════"
    if ! "$PY" -m pytest -q -m "not slow and not local" --timeout=120 -p no:cacheprovider \
            --cov=. --cov-report=json:coverage.json; then
        mark_fail "tests"
    fi
    echo ""
    echo "════ [3/3] 覆盖率门禁（只防倒退）════"
    if ! "$PY" scripts/_gate_coverage.py; then
        mark_fail "coverage"
    fi
fi

echo ""
if [ "$FAILED" = "0" ]; then
    echo "✅ 本地 CI 全过（与 .github/workflows/ci.yml 同口径）"
    exit 0
fi
echo "❌ 未通过的闸门:$FAILED_NAMES"
exit 1
