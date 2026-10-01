"""答案来源审计（_leak_provenance）的判定测试。

对应 2026-10-01 的一次**真实误判**：曾把「基线命中、presolve 没中」的 5 道题判成
"本框架的抽取盲区"，实则那 5 道的附件就是官方 writeup 全文，真值 flag 明文就在里面。
本测试锁住「答案物理存在」这条判据，防止再次把"grep 白给分"误读成"能力"。

变异验证：把附件扫描强制返回 False（`_attachment_plaintext` 打桩），
第一类用例必须**不再**判 att_leak —— 否则说明该判据没真正生效。
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import _leak_provenance as lp  # noqa: E402
from eval.cases import Question  # noqa: E402


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _mkq(tmp_path: Path, *, desc: str = "", att_name: str | None = None,
         att_data: bytes | None = None, flag: str = "flag{abc}") -> Question:
    atts = []
    if att_name is not None:
        p = tmp_path / att_name
        p.write_bytes(att_data if att_data is not None else b"")
        atts.append(str(p))
    return Question(
        id="t_leak_1", title="t", category="crypto", description=desc,
        flag=None, flag_sha256=_sha(flag), attachments=atts,
    )


# ---------------------------------------------------------------- 四档判定

def test_answer_in_attachment_is_att_leak(tmp_path):
    q = _mkq(tmp_path, att_name="cipher.txt", att_data=b"noise flag{abc} noise")
    r = lp.classify(q, tmp_path)
    assert r["provenance"] == "att_leak"
    assert r["attachment_file"] == "cipher.txt"


def test_answer_only_in_description_is_desc_leak(tmp_path):
    q = _mkq(tmp_path, desc="解题：最终得到 flag{abc} 即为答案",
             att_name="cipher.txt", att_data=b"deadbeef")
    r = lp.classify(q, tmp_path)
    assert r["provenance"] == "desc_leak"
    assert r["in_attachment"] is False


def test_desc_inner_token_via_oracle_is_desc_leak(tmp_path):
    """题面只写裸答案（无 flag{} 外壳）时，靠 oracle 命中内层 token。"""
    q = _mkq(tmp_path, desc="每组字母连线的形状对应一个字母，解出 CLCKOUTHK。",
             att_name="cipher.txt", att_data=b"deadbeef", flag="flag{CLCKOUTHK}")
    r = lp.classify(q, tmp_path, oracle={"t_leak_1": "flag{CLCKOUTHK}"})
    assert r["provenance"] == "desc_leak"


def test_answer_nowhere_is_none(tmp_path):
    """附件/描述都没有真值 → provenance=none（由 caller 再分 computed/unsolved）。"""
    q = _mkq(tmp_path, att_name="task.py", att_data=b"print('compute me')")
    r = lp.classify(q, tmp_path)
    assert r["provenance"] == "none"


def test_zip_member_answer_is_att_leak(tmp_path):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner/flag.txt", "flag{abc}\n")
    q = _mkq(tmp_path, att_name="dist.zip", att_data=buf.getvalue())
    r = lp.classify(q, tmp_path)
    assert r["provenance"] == "att_leak"
    assert "dist.zip!" in r["attachment_file"]


# ---------------------------------------------------------------- 变异验证

def test_mutation_disable_attachment_scan(tmp_path, monkeypatch):
    """变异：把附件扫描打桩成恒 False，则「答案在附件里」的题必须掉出 att_leak。"""
    q = _mkq(tmp_path, att_name="cipher.txt", att_data=b"noise flag{abc} noise")
    monkeypatch.setattr(lp, "_attachment_plaintext", lambda *a, **k: (False, ""))
    r = lp.classify(q, tmp_path)
    assert r["provenance"] != "att_leak", \
        "变异失败：禁用附件扫描后仍判 att_leak，说明该判据没真正生效"


def test_mutation_break_sha_compare(tmp_path, monkeypatch):
    """变异：把候选 sha 比对改成恒不等，att_leak 必须消失。"""
    q = _mkq(tmp_path, att_name="cipher.txt", att_data=b"noise flag{abc} noise")
    monkeypatch.setattr(lp, "_sha", lambda b: "0" * 64)
    r = lp.classify(q, tmp_path)
    assert r["provenance"] != "att_leak"
