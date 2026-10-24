# -*- coding: utf-8 -*-
"""external_unseen 真题源 + 本轮接线修复的回归锁（2026-10-21）。

覆盖四件事，全部有真题实证背文：
  1. `load_external_cases`：真题 JSON → case 字典（魔数路由适配器、载荷不在盘
     的题不进分母、只有 sha256 没有明文）；
  2. `_truth_match`：从输出文本抽候选再哈希比对 —— 判分器不持明文（拿已知
     明文做 `in` 判断就等于把答案写进判分器）；
  3. `Question.__post_init__` 类别归一化：rev→reverse。不归一则
     `inventory("rev")` 按 adapters 声明的 categories 过滤，rea_probe
     （声明 ["reverse","misc"]）从工具清单里消失 —— 实测 agent 9 步只调
     file_analyze，真题 0 解；
  4. `_normalize_lock`：history 上 lock 出现过 payloads→payloads→payloads
     三层套娃，读取必须按值形态递归归一；
  5. plan 嵌套拍平：LLM 稳定输出 {"action":"tool","plan":{"lane":...}}，
     执行器只读顶层 → 参数全丢、四次调用观察逐字相同。

标 local：需要 external_unseen 真题载荷在盘（gitignore 的数据目录）。
    .venv/Scripts/python.exe -m pytest tests/test_external_unseen_source.py -q
"""
from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

pytestmark = pytest.mark.local

_EXT_QDIR = os.path.join(_ROOT, "benchmarks", "external_unseen", "questions")
_PAYLOADS = os.path.join(
    _ROOT, "data", "questions_ext_cybench", "_attachments", "rev")


def _payload_on_disk() -> bool:
    """真题载荷在不在盘（data/ 按池策略 gitignore，CI 上会缺）。"""
    for q in ("hackthebox_cyber_apocalypse_2024_reversing_very_easy_packedaway",
              "hackthebox_cyber_apocalypse_2024_reversing_easy_crushing",
              "hackthebox_cyber_apocalypse_2024_reversing_hard_flecksofgold"):
        if not os.path.isdir(os.path.join(_PAYLOADS, q)):
            return False
    return True


needs_payloads = pytest.mark.skipif(
    not _payload_on_disk(), reason="external_unseen 真题载荷不在盘（data/ gitignore）")


# ── 1+2. external loader 与 sha256 判分 ──────────────────────────────

@needs_payloads
def test_load_external_cases_routes_by_magic():
    """三题都应被魔数路由到 rea_probe，且带 sha256 真值、不带明文。"""
    from benchmarks.local_real.run_e2e import load_external_cases
    cases = load_external_cases()
    ids = {k for k in cases if "reversing" in k}
    assert len(ids) == 3, f"期望 3 道 reversing 真题，实得 {sorted(ids)}"
    for cid, c in cases.items():
        if "reversing" not in cid:
            continue
        assert c["adapter"] == "rea_probe", f"{cid} 应路由到 rea_probe"
        assert len(c["flagSha256"]) == 64, f"{cid} 真值必须是 sha256"
        assert "flag" not in c or not c.get("flag"), f"{cid} 不得携带明文 flag"


@needs_payloads
def test_load_external_cases_crushing_has_two_attachments():
    """crushing 的 message.txt.cz 是解题本体，不能被过滤成单附件。"""
    from benchmarks.local_real.run_e2e import load_external_cases
    cases = load_external_cases()
    crush = [c for k, c in cases.items() if "crushing" in k][0]
    names = sorted(os.path.basename(a) for a in crush["attachments"])
    assert names == ["crush", "message.txt.cz"], names


@needs_payloads
def test_truth_match_rejects_wrong_hash():
    """sha256 不匹配的候选必须返回 None —— 判分不许放水。

    夹具纪律（2026-10-21 提交前审查修正）：**绝不使用真题真实 flag 当夹具**。
    原实现用 crushing 的真 flag + 真 sha256，等于把明文答案写进 tracked 测试文件
    ——agent 在 ctf_agent 工作目录里 grep 就能拿到（基准污染）。此处改用合成夹具，
    语义完全相同（错 hash 拒收 / 句内剥出）。
    """
    from benchmarks.local_real.run_e2e import _truth_match
    fix = "HTB{f1xtur3_n0t_4_r34l_fl4g_2026}"
    sha = "611a41c2cdef32c8f153c22e7fabaded42e3255c8376598c1bab9639c81e0405"
    assert _truth_match(fix, sha) == fix
    assert _truth_match("HTB{wrong}", sha) is None
    assert _truth_match("no flag here", sha) is None
    # 句子里抄写的也要能剥出来（agent 常把 flag 嵌在句子里）
    assert _truth_match(f'the flag is "{fix}" ok', sha) == fix


# ── 3. Question 类别归一化 ────────────────────────────────────────────

def test_question_post_init_normalizes_category():
    """rev→reverse：不归一则 inventory 过滤把 rea_probe 滤掉（真题 0 解根因）。"""
    from eval.cases import Question, normalize_category
    assert normalize_category("rev") == "reverse"
    assert normalize_category("forensics") == "misc"
    assert normalize_category("reverse") == "reverse"   # 幂等
    assert normalize_category("unknown_cat") == "unknown_cat"  # 未知不改写
    q = Question(id="t", title="t", category="rev", description="d")
    assert q.category == "reverse"
    # from_dict 与直接构造必须同构（此前只有 from_dict 归一化）
    q2 = Question.from_dict({"id": "t2", "title": "t", "category": "rev"})
    assert q2.category == q.category


def test_inventory_visible_for_rev_category():
    """rev 题的工具清单里必须看得到 rea_probe（注册≠可见的回归锁）。"""
    from tools.registry import ToolRegistry
    from tools.adapters.rea_probe import ReaProbeAdapter
    reg = ToolRegistry()
    reg.register(ReaProbeAdapter())
    items = {it["name"] for it in reg.inventory("rev")}
    assert "rea_probe" in items, "rev 题看不到 rea_probe（归一化 regression）"


# ── 4. lock 归一化 ────────────────────────────────────────────────────

def test_normalize_lock_collapses_nested_history():
    """三层套娃 + 散落各层的 qid 条目必须归一成一层，且不丢条目。"""
    from scripts._fetch_cybench_payloads import _normalize_lock
    nested = {
        "repo": "r", "commit": "c",
        "payloads": {
            "repo": "r", "commit": "c",
            "payloads": {
                "repo": "r", "commit": "c",
                "payloads": {"q1": {"a": "0" * 64}},
                "q2": {"b": "1" * 64},
            },
            "q3": {"c": "2" * 64},
        },
    }
    out = _normalize_lock(nested)
    assert set(out) == {"q1", "q2", "q3"}, f"归一后应含全部 qid：{sorted(out)}"
    assert out["q1"] == {"a": "0" * 64}
    assert out["q3"] == {"c": "2" * 64}


def test_normalize_lock_clean_file_passthrough():
    """干净结构原样通过（不能把正常文件也拆散）。"""
    from scripts._fetch_cybench_payloads import _normalize_lock
    clean = {"repo": "r", "commit": "c",
             "payloads": {"q1": {"a": "0" * 64}}}
    assert _normalize_lock(clean) == {"q1": {"a": "0" * 64}}


def test_normalize_lock_garbage_safe():
    """非 dict / 空 / 怪结构不许炸（lock 损坏时脚本要能继续跑）。"""
    from scripts._fetch_cybench_payloads import _normalize_lock
    assert _normalize_lock(None) == {}
    assert _normalize_lock([]) == {}
    assert _normalize_lock({"payloads": "oops"}) == {}


# ── 5. plan 嵌套拍平 ─────────────────────────────────────────────────

def test_plan_flatten_merges_nested_params():
    """{"action":"tool","plan":{"lane":...}} 的 lane 必须到达执行器读的顶层。"""
    # 与 core/phases.py plan_step 的拍平逻辑同构（此处锁行为，防回归）
    def flatten(result):
        if result and isinstance(result.get("plan"), dict):
            nested = result.pop("plan")
            for k, v in nested.items():
                if result.get(k) is None:
                    result[k] = v
        return result

    r = flatten({"action": "tool", "tool": "rea_probe",
                 "plan": {"lane": "decompile_batch", "name_filter": "main"}})
    assert r["lane"] == "decompile_batch"
    assert r["name_filter"] == "main"
    # 嵌套里连 tool 名都有的形态
    r2 = flatten({"action": "tool", "plan": {"tool": "rea_probe", "lane": "elf"}})
    assert r2["tool"] == "rea_probe" and r2["lane"] == "elf"
    # 显式顶层优先，不被嵌套覆盖
    r3 = flatten({"action": "tool", "tool": "x", "lane": "auto",
                  "plan": {"lane": "elf"}})
    assert r3["lane"] == "auto"
    # 无嵌套原样
    r4 = flatten({"action": "reason", "detail": "d"})
    assert r4 == {"action": "reason", "detail": "d"}


# ── 6. rea_probe 新增确定性行为（不依赖 Ghidra 的部分） ────────────────

def test_crt_symbol_classifier():
    """自定义函数 vs CRT/模板库：flecks 1557 函数里 1550 个是库，不滤会刷屏。"""
    from tools.adapters.rea_probe import _is_crt_symbol
    for custom in ("main", "add_char_to_map", "serialize_and_output", "list_len",
                   "rand_pos", "operator()", "v",
                   "_Z8rand_posd.constprop.0"):
        assert not _is_crt_symbol(custom), f"{custom} 是题目逻辑，不该判 CRT"
    for crt in ("_init", "_fini", "_start", "deregister_tm_clones",
                "frame_dummy", "__do_global_dtors_aux", "__libc_start_main",
                "_ZSt4cout", "_ZNSt8ios_base4InitC1Ev",
                "_ZN5flecs1_8free_objINS0_13each_delegateEZ4mainEEEE",
                "printf@plt".split("@")[0] + "@plt"):
        assert _is_crt_symbol(crt), f"{crt} 是 CRT/库符号，该判 CRT"


def test_filter_separator_normalization():
    """逗号过滤词必须换成空格再进命令行（批处理把逗号当参数分隔符，
    四词过滤只导出 1 个函数且 EXPORT_DONE 照报成功 —— 不比对候选数发现不了）。"""
    import re
    def norm(flt: str) -> str:
        return re.sub(r"[,;|]+", " ", flt).strip() or "*"
    assert norm("a,b,c") == "a b c"
    assert norm("a;b|c") == "a b c"
    assert norm("main") == "main"          # 单词不受影响
    assert norm("") == "*"
    assert norm(",") == "*"


def test_elf_hint_fires_on_real_payload():
    """crush 的 elf lane 必须带升级提示（真题 crushing agent 四连 lane=auto
    被死循环闸止损，缺的就是这条确定性提示）。"""
    if not _payload_on_disk():
        pytest.skip("external_unseen 真题载荷不在盘")
    import asyncio
    from tools.adapters.rea_probe import ReaProbeAdapter
    crush = os.path.join(_PAYLOADS,
                         "hackthebox_cyber_apocalypse_2024_reversing_easy_crushing",
                         "crush")
    out = asyncio.run(ReaProbeAdapter().run({"path": crush, "lane": "elf"}))
    assert "升级提示" in out.text, "elf lane 未给出 decompile_batch 升级提示"
    assert "add_char_to_map" in out.text


# ── 6. token 口径落盘（2026-10-21）──────────────────────────────────

class _FakeBudget:
    """假 BudgetTracker：只暴露 run_e2e 读取的两个面。"""

    def __init__(self, used: int, cap: int):
        self._used = used
        self.config = SimpleNamespace(per_question_token_budget=cap)

    def usage(self, _qid: str) -> int:
        return self._used


def _token_usage(solver, qid):
    from benchmarks.local_real.run_e2e import _token_usage as _fn
    return _fn(solver, qid)


def test_token_usage_helper_reads_budget():
    """`_token_usage` 必须把 solver.budget 的真实记账读出来（used/cap 双口径）。"""
    got = _token_usage(SimpleNamespace(budget=_FakeBudget(1234, 80000)), "q1")
    assert got == {"used": 1234, "cap": 80000}


def test_token_usage_helper_defensive():
    """没挂 budget / budget 炸了都不许带崩跑分记录——返回空 dict。"""
    assert _token_usage(SimpleNamespace(), "q1") == {}

    class _Boom:
        config = SimpleNamespace(per_question_token_budget=1)
        def usage(self, _qid):
            raise RuntimeError("boom")
    assert _token_usage(SimpleNamespace(budget=_Boom()), "q1") == {}


def test_external_agent_record_carries_tokens(monkeypatch):
    """真题 agent 级记录必须带 tokens 字段（取证 2026-10-21：七份 crushing 运行
    记录无一带 token 口径，「80k 是否偏紧」无法复算——本锁防再次丢失）。"""
    import asyncio
    import run as run_mod
    from benchmarks.local_real import run_e2e

    async def _fake_solver(question, attempt=0, correction=None):
        return {"task_id": question.id, "flag": None, "error": None,
                "steps": [], "duration_ms": 1, "retries": 0}
    _fake_solver.budget = _FakeBudget(4321, 80000)
    monkeypatch.setattr(run_mod, "build_solver", lambda **kw: _fake_solver)

    case = {"id": "ext_cybench_hackthebox_cyber_apocalypse_2024_reversing_easy_crushing",
            "title": "t", "category": "reverse", "description": "d",
            "attachments": ["crush", "message.txt.cz"],
            "flagPattern": None, "flagSha256": "0" * 64, "difficulty": "easy"}
    rec = asyncio.run(run_e2e.run_external_agent_case(
        "ext::crushing", case, "deepseek", None, timeout=5))
    assert rec["tokens"] == {"used": 4321, "cap": 80000}, (
        f"记录缺 token 口径：{rec}——预算类决策将再次无法取证")


# ── 5. 泄漏回归锁：仓库内不得出现能命中基准真值的明文 ─────────────────────

def test_no_benchmark_answer_plaintext_in_repo():
    """仓库内任何明文候选都不得与基准真值 sha256 命中（泄漏回归锁，2026-10-21）。

    提交前审查实证：本文件曾用 crushing 的真 flag + 真 sha256 当夹具——
    agent 工作目录就在 ctf_agent，`grep -r "HTB{" .` 即得，判分器还会认
    （哈希逐字相等）。已改用合成夹具（HTB{f1xtur3_n0t_4_r34l_fl4g_2026}）。

    本锁不复用「HTB{...} 形状」判据（合成夹具也长这样，会误报），而是直接拿
    候选明文哈希与基准 79 题 flag_sha256 集合求交：命中即泄漏，零误报。
    排除 data/：运行日志如实记录已提交 flag，而解出的题按设计会自动离池
    （README 口径红线第 2 条），不构成对当前分母的污染。
    """
    import hashlib
    import re

    pat = re.compile(r"(?:HTB|flag|DASCTF|FLAG)\{[^}\s]{6,}\}")
    truths = set()
    qdir = os.path.join(_ROOT, "benchmarks", "external_unseen", "questions")
    for fn in os.listdir(qdir):
        if fn.endswith(".json"):
            with open(os.path.join(qdir, fn), encoding="utf-8") as f:
                sha = str((json.load(f) or {}).get("flag_sha256") or "").lower()
            if len(sha) == 64:
                truths.add(sha)

    hits = []
    for dirpath, dirnames, filenames in os.walk(_ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in {".git", ".venv", "data", "__pycache__", ".pytest_cache"}]
        for fn in filenames:
            if not fn.endswith((".py", ".json", ".md", ".txt", ".yml", ".yaml", ".java", ".sh")):
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 5_000_000:
                    continue
                with open(fp, encoding="utf-8", errors="ignore") as f:
                    txt = f.read()
            except OSError:
                continue
            for cand in pat.findall(txt):
                if hashlib.sha256(cand.encode()).hexdigest() in truths:
                    hits.append((os.path.relpath(fp, _ROOT), cand[:24] + "…"))
                    break
    assert not hits, f"基准答案明文出现在仓库内（agent grep 即得）: {hits[:5]}"
