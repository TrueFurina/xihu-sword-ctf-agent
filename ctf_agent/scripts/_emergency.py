"""正式赛紧急救急脚本：卡关/意外风险一键处置（2026-08-20 补缺口）。

正式赛 3h 内遇到意外时的救急动作：
    python scripts/_emergency.py --status     # 救急状态检查（provider/超时/并发/进度）
    python scripts/_emergency.py --downgrade  # 熔断降级（单 provider + 低并发 + 快速失败）
    python scripts/_emergency.py --finish     # 3h 快结束强制收尾（生成解题报告 + 汇总）

依赖：core.solve_progress（进度）、report.generator（报告）、winreg（降级写配置）。
"""

import argparse
import os
import sys
import time
import winreg

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def _set_env(name: str, value: str) -> None:
    """写注册表环境变量（新进程生效）。"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)
        print(f"  ✅ 已写 {name}={value}")
    except OSError as exc:
        print(f"  ⚠️ 写 {name} 失败（{exc}），手动 setx {name} {value}")


def status() -> dict:
    """救急状态检查：provider/并发/超时/进度。"""
    from scripts._provider_failover import _PROVIDERS, _probe

    def get_env(name: str) -> str:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                v, _ = winreg.QueryValueEx(k, name)
                return str(v)
        except OSError:
            return ""

    def get_key(name: str) -> str:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                v, _ = winreg.QueryValueEx(k, name)
                return str(v)
        except OSError:
            return ""

    # provider 探测（前 4 个 + aliyun 1 个代表性）
    avail = []
    for name, url, model, keyenv in _PROVIDERS[:5]:
        if _probe(name, url, model, get_key(keyenv)).get("ok"):
            avail.append(name.split()[0])
    print(f"① 可用 provider: {avail or '❌ 无！'}")
    print(f"② 当前 provider: {get_env('CTF_AGENT_LLM_PROVIDER') or 'deepseek(默认)'}")
    print(f"③ 并发: {get_env('CTF_AGENT_MAX_CONCURRENCY') or '默认'}")
    print(f"④ 单题超时: {get_env('CTF_AGENT_LLM_TIMEOUT') or '默认'}")
    # 进度
    from core.solve_progress import get_progress

    sp = get_progress()
    s = sp.summary()
    print(f"⑤ 进度: 已解 {s.get('solved_count', 0)} 题 / 尝试 {s.get('attempts_count', 0)} 次")
    # 熔断状态（P0 2026-08-21）：展示已熔断 provider，便于赛中判断是否该换 key/源
    try:
        from llm.client import circuit_summary
        circuits = circuit_summary()
        if circuits:
            opened = [p for p, v in circuits.items() if v.get("open")]
            print(f"⑥ 熔断状态: {'❌ 已熔断: ' + ', '.join(opened) if opened else '无熔断'}"
                  f"（详情: {circuits}）")
        else:
            print("⑥ 熔断状态: 无（全部 provider 正常）")
    except Exception:
        pass
    return {"providers": avail, "solved": s.get("solved_count", 0)}


def downgrade() -> None:
    """熔断降级：单 provider + 低并发 + 快速失败 + 关重型（LLM 故障/限流时救急）。"""
    print("=== 熔断降级（LLM 故障/限流救急）===")
    _set_env("CTF_AGENT_LLM_PROVIDER", "baidu")      # 单 provider（千帆最稳）
    _set_env("CTF_AGENT_MAX_CONCURRENCY", "1")        # 并发 1（防限流）
    _set_env("CTF_AGENT_UPGRADE_AFTER", "99")         # 关闭重型模型升级（省额度）
    _set_env("CTF_AGENT_LLM_TIMEOUT", "60")           # 单请求 60s 快速失败
    _set_env("CTF_AGENT_PER_Q_BUDGET", "20000")       # 单题预算收紧（快速失败）
    print("降级完成：单 provider baidu + 并发 1 + 快速失败 + 关重型")
    print("恢复：删除以上环境变量或重设（setx /d 或直接覆盖）")


def _build_report_records_from_progress() -> list[dict]:
    """从 solve_progress.json 构造 poller_records 真实数据。

    修复（2026-08-21 17:02 P0）：原 finish() 硬编码 poller_records=[]，
    生成的报告是空占位（题目数 0），不满足手册第 8 条"报告必须含真实数据"。
    本函数从 solve_progress 的 solved/attempts 重建：
      - solved: 平台已确认解出（accepted=True）
      - attempts 的 cat= 字段回填 category
      - flag 优先取 solved.flag，空则回填 known_flags（明文可见时的兜底）
    """
    import re
    from core.solve_progress import get_progress

    snap = get_progress().snapshot()
    solved = snap.get("solved", {}) or {}
    attempts = snap.get("attempts", {}) or {}

    # 题目类别回填：从 attempts[].result 提取 "cat=xxx"
    def _cat(qid: str) -> str:
        for a in attempts.get(qid, []):
            m = re.search(r"cat=([a-z]+)", str(a.get("result", "")))
            if m:
                return m.group(1)
        return ""

    # 明文 flag 兜底（solve_progress 只存"平台已解出"标记，部分场景 flag 明文
    # 在 goal_log 或历史记录中；此处收录已知明文 flag，空则留给报告"未解出"）
    known_flags = {
    }

    records = []
    for qid, info in sorted(solved.items()):
        note = str(info.get("note", ""))
        flag = str(info.get("flag", "") or "")
        if not flag and qid in known_flags:
            flag = known_flags[qid]
        records.append({
            "challenge_id": str(qid),
            "title": f"{_cat(qid).upper() or 'CHALLENGE'}-{str(qid)[-2:]}",
            "category": _cat(qid),
            "flag": flag,
            "accepted": bool("hasSolved" in note or info.get("accepted")),
            "detail": note,
            "duration_s": 0,
            "error": "",
        })
    return records


def finish() -> None:
    """3h 快结束强制收尾：生成解题报告 + 汇总（手册第 8 条硬性要求）。"""
    print("=== 强制收尾（生成解题报告）===")
    try:
        from report.generator import generate_report, save_report
        from run import _solve_logs

        # P0 修复（2026-08-21）：不再硬编码空 records，从 solve_progress 重建真实数据
        poller_records = _build_report_records_from_progress()
        md = generate_report(poller_records=poller_records, solve_logs=_solve_logs,
                             stage="正式赛收尾")
        path = save_report(md)
        print(f"📋 解题报告已生成: {path}（{len(md)} 字符，记录 {len(poller_records)} 条）")
    except Exception as exc:
        print(f"⚠️ 报告生成失败（{exc}）——手动检查 data/results/")
    from core.solve_progress import get_progress

    s = get_progress().summary()
    print(f"📊 最终进度: 已解 {s.get('solved_count', 0)} 题")
    print("提示: 报告路径 data/reports/，提交前确认含概览/题目详情/合规声明")


def main() -> None:
    parser = argparse.ArgumentParser(description="正式赛紧急救急脚本")
    parser.add_argument("--status", action="store_true", help="救急状态检查")
    parser.add_argument("--downgrade", action="store_true", help="熔断降级（LLM 故障救急）")
    parser.add_argument("--finish", action="store_true", help="3h 快结束强制收尾（生成报告）")
    args = parser.parse_args()

    if args.downgrade:
        downgrade()
    elif args.finish:
        finish()
    else:
        status()


if __name__ == "__main__":
    main()
