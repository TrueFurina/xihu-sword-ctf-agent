"""本地真值基准的运行器：适配器级（无 LLM）+ Agent 级（真实 LLM）。

两级测量的差别是本次建设的重点：
  - adapter 级：**假定工具选对了**，只测「能力本身能不能把 flag 拿出来」。
    快、确定性、可进 CI，但证明不了 agent 会不会选这个工具。
  - agent 级：走 build_solver 的**生产链路**（presolve → plan → act → extract_flag
    → 反幻觉闸 → 判分），真 LLM、真工具。这才是「能不能拿分」的口径。

用法：
    python benchmarks/local_real/run_e2e.py --mode adapter
    python benchmarks/local_real/run_e2e.py --mode agent --provider deepseek --case pcap_br
    python benchmarks/local_real/run_e2e.py --mode agent --provider deepseek --timeout 240
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import traceback

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

from build_artifacts import _SEEDS, synth_flag  # noqa: E402

_MANIFEST = os.path.join(_HERE, "manifest.json")


def load_cases(only: str | None = None) -> dict:
    if not os.path.isfile(_MANIFEST):
        raise SystemExit(f"缺少 {_MANIFEST}，先跑 build_artifacts.py")
    cases = json.load(open(_MANIFEST, encoding="utf-8"))["cases"]
    return {k: v for k, v in cases.items() if only in (None, k)}


# ── 真题源：external_unseen（真 CTF 题，载荷在盘，真值只有 sha256）───────
_EXT_QDIR = os.path.join(_ROOT, "benchmarks", "external_unseen", "questions")

#: 载荷魔数 → 适配器。反过来写（先判更特殊的）：wasm 与 pcap 的魔数都不与 PE/ELF 冲突。
_MAGIC_ADAPTERS = (
    (b"\x00asm", "wasm_probe"),
    (b"\x7fELF", "rea_probe"),
    (b"MZ", "rea_probe"),
    (b"\xd4\xc3\xb2\xa1", "pcap_probe"),      # pcap LE
    (b"\xa1\xb2\xc3\xd4", "pcap_probe"),      # pcap BE
    (b"\x0a\x0d\x0d\x0a", "pcap_probe"),      # pcapng
)


def load_external_cases(only: str | None = None) -> dict:
    """读 external_unseen 真题。

    与本地合成题的根本区别：**这里没有 `flag` 字段**，只有 `flag_sha256`。
    所以判分一律走 sha256 比对，且适配器级也要从输出文本里抽候选再哈希 ——
    不能像合成题那样拿已知明文做 `in` 判断（那就等于把答案写进了判分器）。
    """
    import glob

    out = {}
    for p in sorted(glob.glob(os.path.join(_EXT_QDIR, "*.json"))):
        d = json.load(open(p, encoding="utf-8"))
        atts = [a for a in (d.get("attachments") or []) if os.path.isfile(a)]
        if not atts:
            continue                      # 载荷不在盘上的题不进分母，如实缩小分母
        with open(atts[0], "rb") as f:
            magic = f.read(4)
        adapter = next((n for m, n in _MAGIC_ADAPTERS if magic.startswith(m)), None)
        out[d["id"]] = {
            "id": d["id"],
            "title": d.get("title") or d["id"],
            "category": d.get("category") or "",
            "description": d.get("description") or "",
            "attachments": atts,
            "flagPattern": d.get("flag_pattern") or r"[A-Za-z0-9_]{1,20}\{[^}\s\x00]{3,120}\}",
            "flagSha256": d.get("flag_sha256") or d.get("flag") or "",
            "adapter": adapter,
            "hiddenBy": f"真实赛题载荷（{len(atts)} 个附件）",
            "bytes": sum(os.path.getsize(a) for a in atts),
        }
    return {k: v for k, v in out.items() if only in (None, k)}


def _truth_match(text: str, sha256: str) -> str | None:
    """从输出文本里抽 flag 候选，返回 sha256 命中的那条；不命中返回 None。

    为什么不能直接用已知明文做 `in` 判断：真题侧根本没有明文，判分器一旦
    持有明文就成了泄漏源。这里只做「抽候选 → 哈希 → 比对 sha256」。
    """
    import hashlib

    from tools.adapters.flag_scan_adapter import FLAG_PATTERNS

    if not sha256 or len(sha256) != 64:
        return None
    cands: list[str] = []
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            v = m.group(0)
            if v not in cands:
                cands.append(v)
    # 去掉前后空白与首尾包裹字符再各试一次：agent 常常把 flag 抄进句子里
    for v in list(cands):
        s = v.strip().strip("\"'`.,;:()[]{}")
        if s and s not in cands:
            cands.append(s)
    for v in cands:
        for probe in (v, v.strip()):
            if hashlib.sha256(probe.encode("utf-8", "surrogateescape")).hexdigest() == sha256:
                return probe
    return None


# ── 适配器级：确定性，无 LLM ────────────────────────────────────────────
def run_adapter_case(cid: str, case: dict) -> dict:
    """直接调对应适配器，看 ToolOutput.text 里有没有真 flag。"""
    flag = synth_flag(_SEEDS[cid])
    path = case["artifact"]
    t0 = time.time()
    err = ""
    text = ""
    contract = {}
    try:
        if cid == "pcap_br":
            from tools.adapters.pcap_probe import PcapProbeAdapter
            out = asyncio.run(PcapProbeAdapter().run({"path": path}))
        elif cid == "pe_upx":
            from tools.adapters.rea_probe import ReaProbeAdapter
            out = asyncio.run(ReaProbeAdapter().run({"path": path, "lane": "auto"}))
        elif cid == "wasm_data":
            from tools.adapters.wasm_probe import WasmProbeAdapter
            out = asyncio.run(WasmProbeAdapter().run({"path": path}))
        else:
            raise ValueError(cid)
        text = out.text
        try:
            contract = json.loads(out.raw or "{}")
        except Exception:  # noqa: BLE001
            contract = {}
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    dt = time.time() - t0
    # 拆段工件（wasm）：适配器只负责把两段都摊到上下文里，拼接是 agent 的事。
    # 所以适配器级判「两段都在」，agent 级仍判整串。
    # 拆段工件：两段都必须在输出里（算得出来，所以不把明文写进 manifest）
    want = [flag[:len(flag) // 2], flag[len(flag) // 2:]] if case.get("splitFlag") else None
    hit = all(p in text for p in want) if want else (flag in text)
    return {
        "case": cid, "mode": "adapter", "matched": hit, "ms": round(dt * 1000),
        "degraded": contract.get("degraded"), "error": err,
        "textBytes": len(text),
        "note": "" if hit else ("适配器未把 flag 输出到上下文" if not err else "适配器异常"),
    }


# ── 真题适配器级：sha256 判分，判分器不持明文 ──────────────────────────
def run_external_adapter_case(cid: str, case: dict) -> dict:
    """对真题载荷直接跑适配器，从输出文本抽候选再哈希比对 flag_sha256。

    与合成题的三点区别：
      1. 没有明文可比，判分走 _truth_match（抽候选→哈希→比对）；
      2. 载荷按魔数路由适配器（case["adapter"]），不是写死的 case id；
      3. 多附件（如 crushing 的 crush + message.txt.cz）要**逐个**跑——
         判分只要任一附件输出命中即算该题命中，但记录每个附件的去向，
         因为「哪个附件出的」本身就是信息（message.txt.cz 可能才是正解）。
    """
    t0 = time.time()
    texts: list[tuple[str, str]] = []      # (附件名, 输出文本)
    err = ""
    contract: dict = {}
    adapter = case.get("adapter")
    try:
        if not adapter:
            raise ValueError(f"魔数未识别，无适配器可跑：{case['attachments']}")
        for path in case["attachments"]:
            out = _run_adapter_by_name(adapter, path)
            texts.append((os.path.basename(path), out.text))
            try:
                contract = json.loads(out.raw or "{}")
            except Exception:  # noqa: BLE001
                contract = {}
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    dt = time.time() - t0
    hit_in = ""
    for name, text in texts:
        probe = _truth_match(text, case["flagSha256"])
        if probe:
            hit_in = name
            break
    return {
        "case": cid, "mode": "adapter", "matched": bool(hit_in), "ms": round(dt * 1000),
        "degraded": contract.get("degraded"), "error": err,
        "textBytes": sum(len(t) for _, t in texts),
        "hitIn": hit_in,
        "attachments": [n for n, _ in texts],
        "note": "" if hit_in else (
            "适配器未把真 flag 输出到上下文" if not err else "适配器异常"),
    }


def _run_adapter_by_name(adapter: str, path: str):
    """按适配器名跑单个载荷。ELF 走 rea_probe 的 elf lane。"""
    import asyncio as _asyncio

    if adapter == "rea_probe":
        from tools.adapters.rea_probe import ReaProbeAdapter
        return _asyncio.run(ReaProbeAdapter().run({"path": path, "lane": "auto"}))
    if adapter == "wasm_probe":
        from tools.adapters.wasm_probe import WasmProbeAdapter
        return _asyncio.run(WasmProbeAdapter().run({"path": path}))
    if adapter == "pcap_probe":
        from tools.adapters.pcap_probe import PcapProbeAdapter
        return _asyncio.run(PcapProbeAdapter().run({"path": path}))
    raise ValueError(f"未知适配器 {adapter}")


# ── Agent 级：生产链路 + 真 LLM ─────────────────────────────────────────
def _token_usage(solver, qid: str) -> dict:
    """把本次求解的真实 token 记账带进跑分记录（2026-10-21）。

    背景：跑分记录此前只有 steps/tools/ms，没有 token 口径——「单题预算 80k 是否
    偏紧」只能靠会话 stdout 里的数字，无法复算、无法对照（2026-10-21 取证时即
    因此无法验证「crushing 打到 80,116 被硬停」的说法：七份保存的运行记录无一
    带 budget_exceeded，也无任何 token 字段）。BudgetTracker 已由 run.py 经
    `solver.budget` 暴露，这里只读不写，生产路径零改动。
    """
    try:
        b = getattr(solver, "budget", None)
        if b is None:
            return {}
        return {"used": int(b.usage(qid) or 0),
                "cap": int(getattr(b.config, "per_question_token_budget", 0) or 0)}
    except Exception:  # noqa: BLE001 - 记账读取失败不该炸掉跑分记录本身
        return {}


async def run_agent_case(cid: str, case: dict, provider: str, model: str | None,
                         timeout: float) -> dict:
    from eval.cases import Question
    from run import build_solver

    flag = synth_flag(_SEEDS[cid])
    # 题号绑定工件摘要：presolve 黑板缓存 key 是 question.id，工件重建后同 id
    # 会命中旧缓存（实测：wasm 工件从「整串明文」改成「拆两段」，缓存里仍是旧答案，
    # 0 步直出）。真实赛题附件不会变，但本地基准会反复重建。
    import hashlib

    with open(case["artifact"], "rb") as f:
        _dig = hashlib.sha256(f.read()).hexdigest()[:8]
    q = Question(
        id=f"{case['id']}_{_dig}",
        title=case["title"],
        category=case["category"],
        description=case["description"],
        attachments=[case["artifact"]],
        flag_pattern=r"flag\{[^}]+\}",
        flag_sha256=case["flagSha256"],
        difficulty="easy",
        provenance="self_authored_training",
    )
    solver = build_solver(use_mock=False, is_correct=q.flag_matches,
                          provider=provider, model_override=model,
                          validate_locally=True, wallclock=timeout)
    t0 = time.time()
    err = ""
    out = {}
    try:
        out = await asyncio.wait_for(solver(q, 1), timeout=timeout + 30)
    except asyncio.TimeoutError:
        err = f"timeout({timeout + 30}s)"
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    dt = time.time() - t0
    submitted = (out or {}).get("flag")
    # 记录 agent 实际调用了哪些工具：命中数只说明「拿到了」，工具名才说明「接线生效」
    steps = (out or {}).get("steps") or []
    tools = [str(s.get("action") or "") for s in steps
             if isinstance(s, dict) and str(s.get("action") or "").startswith("tool:")]
    # 2026-10-21 取证补全：tools 只留 tool: 动作，reason 空转不可见——曾把 glm
    # crushing 的 8 步纯推理误诊成「8 步全 file_analyze」。全量动作序列落盘。
    step_actions = [str(s.get("action") or "") for s in steps if isinstance(s, dict)]
    return {
        "case": cid, "mode": "agent", "matched": bool(submitted and q.flag_matches(submitted)),
        "submitted": submitted, "expected": flag if not submitted else "",
        "ms": round(dt * 1000), "error": err or ((out or {}).get("error") or {}).get("detail", ""),
        "steps": len(steps), "tools": tools, "step_actions": step_actions,
        "tokens": _token_usage(solver, q.id),
    }


async def run_external_agent_case(cid: str, case: dict, provider: str, model: str | None,
                                   timeout: float) -> dict:
    """真题 agent 级：多附件全量进题面，sha256 判分，判分器不持明文。"""
    from eval.cases import Question
    from run import build_solver
    import hashlib

    # 题号绑定附件摘要：presolve 黑板缓存 key 是 question.id。真题附件不会变，
    # 但 _payloads.lock 若重拉（同 sha256 同内容）缓存仍应命中——摘要只防
    # 「同 id 不同内容」，不影响同内容复跑。
    _dig = hashlib.sha256(
        "|".join(case["attachments"]).encode("utf-8", "surrogateescape")
    ).hexdigest()[:8]
    q = Question(
        id=f"{case['id']}_{_dig}",
        title=case["title"],
        category=case["category"],
        description=case["description"],
        attachments=list(case["attachments"]),
        flag_pattern=case.get("flagPattern") or r"[A-Za-z0-9_]{1,20}\{[^}\s\x00]{3,120}\}",
        flag_sha256=case["flagSha256"],
        difficulty=(case.get("difficulty") or "easy").lower(),
        provenance="real_past_ctf",
    )
    solver = build_solver(use_mock=False, is_correct=q.flag_matches,
                          provider=provider, model_override=model,
                          validate_locally=True, wallclock=timeout)
    t0 = time.time()
    err = ""
    out = {}
    try:
        out = await asyncio.wait_for(solver(q, 1), timeout=timeout + 30)
    except asyncio.TimeoutError:
        err = f"timeout({timeout + 30}s)"
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
    dt = time.time() - t0
    submitted = (out or {}).get("flag")
    steps = (out or {}).get("steps") or []
    tools = [str(s.get("action") or "") for s in steps
             if isinstance(s, dict) and str(s.get("action") or "").startswith("tool:")]
    # 2026-10-21 取证补全：tools 只留 tool: 动作，reason 空转不可见——曾把 glm
    # crushing 的 8 步纯推理误诊成「8 步全 file_analyze」。全量动作序列落盘。
    step_actions = [str(s.get("action") or "") for s in steps if isinstance(s, dict)]
    return {
        "case": cid, "mode": "agent", "matched": bool(submitted and q.flag_matches(submitted)),
        "submitted": submitted, "expected": "",
        "ms": round(dt * 1000), "error": err or ((out or {}).get("error") or {}).get("detail", ""),
        "steps": len(steps), "tools": tools, "step_actions": step_actions,
        "tokens": _token_usage(solver, q.id),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["adapter", "agent"], default="adapter")
    ap.add_argument("--case", default=None, help="只跑某个 case")
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--model", default="deepseek-flash")
    ap.add_argument("--timeout", type=float, default=240.0)
    ap.add_argument("--json-out", default=os.path.join("data", "results", "local_real",
                                                       "last_run.json"),
                    help="结果落盘路径（默认 data/results 下：跑分结果不是真值，"
                         "不放 benchmarks/ 以免被真值守卫的 schema 审计拦下）")
    ap.add_argument("--source", choices=["local", "external", "all"], default="local",
                    help="local=自建合成基准；external=external_unseen 真题（sha256 判分，"
                         "载荷不在盘上的题如实缩小分母）；all=两个源都跑")
    args = ap.parse_args()

    cases: dict = {}
    if args.source in ("local", "all"):
        cases.update({f"local::{k}": v for k, v in load_cases(args.case).items()})
    if args.source in ("external", "all"):
        # --case 直接透传：本地 id 在真题里没有匹配会返回 {}，由下面的空检查兜底；
        # 反过来 ext_ 前缀的 id 也只命中真题侧。两个源的 id 空间不重叠。
        cases.update({f"ext::{k}": v for k, v in load_external_cases(args.case).items()})
    if not cases:
        raise SystemExit(f"没有匹配的 case（--source {args.source} --case {args.case}）")

    rows = []
    for cid, case in cases.items():
        is_ext = cid.startswith("ext::")
        # 前缀只用于展示与结果区分源；runner 要的是**原始 case id**
        # （本地 runner 用 cid 查 _SEEDS，加前缀会 KeyError —— 实测踩到）。
        raw_id = cid.split("::", 1)[1]
        print(f"[{cid}] {case['hiddenBy']}  {case['bytes']:,} B", flush=True)
        if args.mode == "adapter":
            row = (run_external_adapter_case(cid, case) if is_ext
                   else run_adapter_case(raw_id, case))
            if is_ext:
                print(f"    → {'HIT' if row['matched'] else 'MISS'}  {row['ms']} ms  "
                      f"degraded={row['degraded']}  hitIn={row.get('hitIn') or '-'}  "
                      f"{row['note'] or ''}", flush=True)
            else:
                print(f"    → {'HIT' if row['matched'] else 'MISS'}  {row['ms']} ms  "
                      f"degraded={row['degraded']}  {row['note'] or ''}", flush=True)
        else:
            row = asyncio.run((run_external_agent_case if is_ext else run_agent_case)(
                raw_id, case, args.provider, args.model, args.timeout))
            tag = "PASS" if row["matched"] else "FAIL"
            print(f"    → {tag}  {row['ms'] / 1000:.1f}s  steps={row['steps']}  "
                  f"tools={row.get('tools')}  submitted={row['submitted']}  "
                  f"{row['error'][:120]}", flush=True)
        rows.append(row)

    ok = sum(1 for r in rows if r["matched"])
    print(f"\n== {args.mode} 级：{ok}/{len(rows)} 命中")
    if args.json_out:
        _d = os.path.dirname(os.path.abspath(args.json_out))
        os.makedirs(_d, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"   → {args.json_out}")
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
