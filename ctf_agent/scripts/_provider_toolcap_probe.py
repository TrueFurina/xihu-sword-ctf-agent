#!/usr/bin/env python3
"""provider 能力档案：用最小探针测「能否真正驱动本 agent 循环」（2026-10-10）。

为什么需要
----------
"provider 活着" ≠ "provider 能用"。2026-10-10 实测三家：
  deepseek-chat  ✅ 正常驱动，但 HTTP402 余额不足
  xfyun 星火      ❌ 活着但不产生有效动作（解析失败 4 次、代码兜底 0 次）
  glm-4-flash     ⚠️ 部分产生动作（兜底 4 次）但单步 plan 超时 60s，预算烧光
活着却跑不了循环的 provider，会把整轮跑批变成"基础设施失败伪装成能力数字"。

本脚本对每个候选 provider 跑**同一道题**的最小探针，产出机器可读档案
（benchmarks/provider_probe.json），并给出推荐：优先"活着 + 零解析失败 + 有解"，
否则退"活着 + 零解析失败"。零解析失败是硬指标——解析失败意味着模型吐不出协议格式。

用法
----
  python scripts/_provider_toolcap_probe.py                    # 探针测全部存活 provider
  python scripts/_provider_toolcap_probe.py --providers glm,xfyun
  python scripts/_provider_toolcap_probe.py --question <题 json 路径>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# 🔴 输出文件名必须与 v2 归档器**分开**（2026-10-10 修）：两者曾共用
# benchmarks/provider_capability.json，v2 跑一次就把 v1 的探针数据
# （解析失败数/兜底次数/步数）整段覆盖掉——两种 schema 挤在一个文件名里，
# 后跑的永远是赢家，先跑的结论无声消失。修复=各自独立文件 + 写前 schema 守卫。
OUT = ROOT / "benchmarks" / "provider_probe.json"
PROBE_BUDGET = "20000"
PROBE_WALLCLOCK = "120"


def alive_providers(max_age_h: int = 72) -> dict:
    snap_dir = ROOT / "logs" / "llm_probe"
    if not snap_dir.is_dir():
        return {}
    snaps = sorted(snap_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not snaps:
        return {}
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    return {k: (v.get("status") if isinstance(v, dict) else "?")
            for k, v in (data.get("providers") or {}).items()}


def pick_probe_question(explicit: str = "") -> Path:
    if explicit:
        return Path(explicit)
    qdir = ROOT / "benchmarks" / "external_unseen" / "questions"
    cands = sorted(qdir.glob("*.json"))
    # 取附件最小的那道（探针要快），没有就退回正式基准第一道
    best, best_size = None, None
    for f in cands:
        q = json.loads(f.read_text(encoding="utf-8"))
        atts = q.get("attachments") or []
        size = sum((ROOT / a).stat().st_size for a in atts if (ROOT / a).is_file())
        if best_size is None or size < best_size:
            best, best_size = f, size
    return best or (cands[0] if cands else Path(""))


def probe(provider: str, qfile: Path) -> dict:
    """对单个 provider 跑一题探针，返回能力指标。"""
    tmp_q = ROOT / "data" / "results" / f"_toolcap_{provider}" / "questions"
    tmp_q.mkdir(parents=True, exist_ok=True)
    for f in tmp_q.glob("*.json"):
        f.unlink()
    q = json.loads(qfile.read_text(encoding="utf-8"))
    (tmp_q / f"{q['id']}.json").write_text(json.dumps(q, ensure_ascii=False), encoding="utf-8")
    rdir = ROOT / "data" / "results" / f"_toolcap_{provider}_run"
    log = ROOT / "logs" / f"toolcap_{provider}.log"
    env = dict(os.environ)
    env.update({"CTF_AGENT_INTERNAL_PRESOLVE": "off", "CTF_AGENT_E3": "1",
                "CTF_AGENT_PER_Q_BUDGET": PROBE_BUDGET, "PYTEST_DEBUG_TMPDIR": "1"})
    cmd = [sys.executable, "-m", "eval.benchmark", "--questions-dir", str(tmp_q),
           "--presolve-skip", "--provider", provider, "--wallclock", PROBE_WALLCLOCK,
           "--results-dir", str(rdir), "--limit", "1"]
    t0 = time.time()
    with log.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT)
    dt = time.time() - t0
    text = log.read_text(encoding="utf-8", errors="ignore")
    stats = {
        "provider": provider, "probe_seconds": round(dt, 1),
        "exit_code": proc.returncode,
        "json_parse_failures": len(re.findall(r"无法解析为 JSON", text)),
        "code_salvage_hits": len(re.findall(r"代码动作兜底", text)),
        "parse_samples": len(re.findall(r"\[parse-sample:", text)),
        "steps": len(re.findall(r"步骤#", text)),
        "plan_timeouts": len(re.findall(r"单步 _plan 超时", text)),
        "log": str(log.relative_to(ROOT)) if log.is_relative_to(ROOT) else str(log),
    }
    rep = rdir / "benchmark_report.json"
    if rep.is_file():
        d = json.loads(rep.read_text(encoding="utf-8"))
        s = d.get("summary", {})
        stats["solved"] = s.get("solved", 0)
        stats["total"] = s.get("total", 0)
        stats["tokens"] = s.get("tokens", {}).get("global_total", 0)
        if d.get("results"):
            stats["error"] = d["results"][0].get("error")
    stats["drives_tool_loop"] = bool(
        stats["code_salvage_hits"] or (stats["steps"] and not stats["json_parse_failures"]))
    return stats


def recommend(profiles: list[dict]) -> dict:
    alive = [p for p in profiles if p.get("alive")]
    perfect = [p for p in alive if p.get("json_parse_failures") == 0 and p.get("solved")]
    clean = [p for p in alive if p.get("json_parse_failures") == 0]
    if perfect:
        return {"recommended": perfect[0]["provider"],
                "why": "活着 + 零解析失败 + 探针解出"}
    if clean:
        return {"recommended": clean[0]["provider"],
                "why": "活着 + 零解析失败（探针未解出）"}
    if alive:
        return {"recommended": None,
                "why": "无 provider 同时满足活着与零解析失败——先充值/换模型，别浪费跑批"}
    return {"recommended": None, "why": "无存活 provider"}


def main() -> int:
    ap = argparse.ArgumentParser(description="provider 工具循环能力探针")
    ap.add_argument("--providers", default="")
    ap.add_argument("--question", default="")
    args = ap.parse_args()
    status = alive_providers()
    cands = [p.strip() for p in args.providers.split(",") if p.strip()] or \
            [p for p, st in status.items() if st == "OK"]
    if not cands:
        print("[toolcap] 无存活 provider，先跑 scripts/_probe_providers.py")
        return 3
    qfile = pick_probe_question(args.question)
    if not qfile or not Path(qfile).is_file():
        print("[toolcap] 找不到探针题目")
        return 2
    print(f"[toolcap] 探针题: {Path(qfile).name}｜候选 provider: {cands}")
    profiles = []
    for p in cands:
        print(f"[toolcap] 探测 {p} …")
        st = probe(p, Path(qfile))
        st["alive"] = (status.get(p) == "OK")
        st["status"] = status.get(p, "unknown")
        profiles.append(st)
        print(f"   → 解出 {st.get('solved','?')}/{st.get('total','?')}｜解析失败 "
              f"{st['json_parse_failures']}｜兜底 {st['code_salvage_hits']}｜"
              f"步数 {st['steps']}｜{st['probe_seconds']}s")
    rep = {
        "schema": "provider_capability/v1",
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "probe_question": Path(qfile).name,
        "probe_budget": PROBE_BUDGET, "probe_wallclock": PROBE_WALLCLOCK,
        "metrics": {
            "json_parse_failures": "解析失败次数（>0 = 模型吐不出本 agent 的动作协议）",
            "code_salvage_hits": "代码围栏兜底恢复次数（>0 = 确实产生了动作）",
            "plan_timeouts": "单步 plan 超时次数（>0 = 太慢，预算会烧光）",
            "drives_tool_loop": "综合判定：能产生动作且不靠解析失败",
        },
        "profiles": profiles,
        "recommendation": recommend(profiles),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[toolcap] 档案已写 {OUT}")
    print(f"[toolcap] 推荐: {rep['recommendation']['recommended']}｜依据: {rep['recommendation']['why']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
