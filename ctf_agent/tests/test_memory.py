"""G5 SessionMemory 单测（¥0、零 token、规则式为主，LLM 以 mock 注入）。

覆盖：规则式事实抽取（flag/path/error/cmd）、压缩后长度下降、keep_recent 保留、
关键词检索、LLM 注入语义压缩、get_summary 不泄露完整历史。
"""

from __future__ import annotations

from core.memory import Fact, SessionMemory, _extract_facts
from core.session import CommandRecord


def _rec(cmd: str, stdout: str = "", stderr: str = "", rc: int = 0, ts: str = "2026-09-28") -> CommandRecord:
    return CommandRecord(cmd=cmd, cwd="/tmp/x", stdout=stdout, stderr=stderr,
                         returncode=rc, ts=ts, note="")


def test_extract_flag():
    rec = _rec("python solve.py", stdout="congrats flag{ABC123} done")
    facts = _extract_facts(rec, 1)
    flags = [f for f in facts if f.kind == "flag"]
    assert flags and flags[0].text == "flag{ABC123}"


def test_extract_error():
    rec = _rec("cat flag.txt", stderr="cat: flag.txt: No such file or directory", rc=1)
    facts = _extract_facts(rec, 2)
    errs = [f for f in facts if f.kind == "error"]
    assert errs and "No such file" in errs[0].text


def test_extract_path():
    rec = _rec("ls", stdout="challenge.bin  solve.py  notes.txt")
    facts = _extract_facts(rec, 3)
    paths = [f for f in facts if f.kind == "path"]
    assert any(p.text == "solve.py" for p in paths)


def test_add_accumulates_facts():
    mem = SessionMemory("t")
    mem.add(_rec("step1", stdout="flag{X1}"))
    mem.add(_rec("step2", stdout="flag{X2}"))
    assert mem.step_count() == 2
    assert mem.fact_count() >= 2  # 至少两个 flag 事实
    assert len([f for f in mem.facts if f.kind == "flag"]) == 2


def test_compact_shorter_than_full_transcript():
    # 构造 30 步历史（长会话），compact 后长度应明显小于全量拼接
    mem = SessionMemory("long")
    for i in range(30):
        mem.add(_rec(f"cmd{i}", stdout="some verbose output " * 20))
    full = "\n".join(f"{r.cmd}\n{(r.stdout or '')}" for r in mem.raw_history)
    comp = mem.compact(keep_recent=5)
    assert len(comp) < len(full)
    assert "steps=30" in comp


def test_compact_keeps_recent():
    mem = SessionMemory("kr")
    for i in range(20):
        mem.add(_rec(f"cmd{i}", stdout=f"out{i}"))
    comp = mem.compact(keep_recent=5)
    # 最近 5 条应完整保留
    for i in range(15, 20):
        assert f"cmd{i}" in comp
    # 早期（非关键）应被丢弃
    assert "cmd0" not in comp
    assert "out0" not in comp


def test_compact_keeps_key_fact_in_old_step():
    mem = SessionMemory("kf")
    # 第 1 步有个 flag，后面 19 步全是噪音
    mem.add(_rec("early", stdout="flag{KEEPME}"))
    for i in range(1, 20):
        mem.add(_rec(f"noise{i}", stdout="x" * 50))
    comp = mem.compact(keep_recent=5)
    assert "flag{KEEPME}" in comp  # 旧 step 的关键事实被保留


def test_retrieve_by_keyword():
    mem = SessionMemory("rt")
    mem.add(_rec("a", stdout="flag{FOUND}"))
    mem.add(_rec("b", stdout="nothing here"))
    hits = mem.retrieve("flag")
    assert hits and any("flag{FOUND}" in h.text for h in hits)
    assert all("flag" in h.text.lower() for h in hits)


def test_retrieve_respects_kinds():
    mem = SessionMemory("rk")
    mem.add(_rec("a", stdout="flag{Z} and error: boom", stderr="error: boom"))
    hits = mem.retrieve("e", kinds={"error"})
    assert hits and all(h.kind == "error" for h in hits)
    assert not any(h.kind == "flag" for h in hits)


def test_compact_with_llm_summarizer_called():
    calls = []

    def fake_llm(text: str) -> str:
        calls.append(text)
        return "SUMMARY"

    mem = SessionMemory("llm", llm_summarizer=fake_llm)
    for i in range(20):
        mem.add(_rec(f"cmd{i}", stdout="y" * 50))
    comp = mem.compact(keep_recent=5, llm=fake_llm)
    # 旧 step（非最近 5）应触发 LLM 语义摘要
    assert calls, "LLM 摘要器应被调用"
    assert "SUMMARY" in comp


def test_get_summary_does_not_leak_full_history():
    mem = SessionMemory("gs")
    for i in range(15):
        mem.add(_rec(f"step_{i:02d}", stdout="verbose " * 30))
    summary = mem.get_summary()
    # 旧的非关键命令（前 5 步 = step_00..step_04）应被压缩丢弃
    assert "step_00" not in summary
    assert "step_01" not in summary
    # 最近 10 条（step_05..step_14）应保留
    assert "step_14" in summary
