"""严格纠正护栏：断言仓库内不存在泄露式假验证（RDD 红线）。

违规定义：
  (1) 任何 .py 含真实 10733 flag 硬编码字面量；
  (2) scripts/demo_llm_rag_solve.py 仍预植答案 (EXPECTED =)。

与 _merge_gate._LEAKED_REAL_FLAG 同源，但用拼接构造，避免本测试文件自身
被「全仓扫描」当成泄露字面量命中。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "ctf_agent"))

_LEAKED_REAL_FLAG = "rabbits6sc5mpl8" + "x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8x6s9w6n6nc5mpl8"


def _iter_py():
    for d in ("scripts", "knowledge", "core", "agents", "tests"):
        base = os.path.join(ROOT, "ctf_agent", d)
        for root, _, files in os.walk(base):
            if ".venv" in root:
                continue
            for fn in files:
                if fn.endswith(".py"):
                    yield os.path.join(root, fn)


def test_no_hardcoded_real_flag():
    hits = []
    for p in _iter_py():
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if _LEAKED_REAL_FLAG in txt:
            hits.append(p)
    assert not hits, f"泄露式硬编码真实 flag 出现在：{hits}"


def test_demo_not_preplanting_answer():
    p = os.path.join(ROOT, "ctf_agent", "scripts", "demo_llm_rag_solve.py")
    if not os.path.isfile(p):
        return
    txt = open(p, encoding="utf-8", errors="ignore").read()
    assert "EXPECTED =" not in txt, "demo_llm_rag_solve.py 仍预植答案 (EXPECTED =)"
    assert _LEAKED_REAL_FLAG not in txt, "demo 仍含泄露真实 flag"
