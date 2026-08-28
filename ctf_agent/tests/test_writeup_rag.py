"""Writeup RAG（IDEA-5 务实落地）单元测试。

覆盖：BM25 排序、语料加载、retrieve 字段、混合嵌入重排、skills 摄入、
prompts 知识注入块、以及 env 闸（默认关=零回归）。
全部离线、确定性、零外部依赖（嵌入重排用伪 embed_fn 验证融合逻辑）。
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # ctf_agent/
sys.path.insert(0, str(ROOT))

from knowledge.bm25 import BM25, tokenize  # noqa: E402
from knowledge.writeup_rag import WriteupIndex  # noqa: E402
from core.main_agent import AgentContext  # noqa: E402
from core.prompts import build_plan_prompt  # noqa: E402

import pytest  # noqa: E402


# ── BM25 ──
def test_tokenize_mixed_cn_en():
    toks = tokenize("RSA 费马分解 fermat_123")
    # 英文/代码 token 整体保留，CJK 按单字切分（无需 jieba）
    assert "rsa" in toks and "费" in toks and "马" in toks and "fermat_123" in toks


def test_bm25_ranks_relevant_first():
    bm = BM25()
    bm.add("a", tokenize("apple fruit red"))
    bm.add("b", tokenize("car engine machine"))
    bm.build()
    scored = bm.search(tokenize("fruit"), top_k=2)
    assert scored[0][1] == "a"


# ── WriteupIndex：语料 + 检索 ──
def test_load_corpus_jsonl_and_retrieve(tmp_path):
    p = tmp_path / "corpus.jsonl"
    p.write_text(
        json.dumps({"id": "w1", "title": "RSA 费马分解", "category": "crypto",
                    "text": "RSA 因式分解 费马 p q 接近" }) + "\n"
        + json.dumps({"id": "w2", "title": "UPX 脱壳", "category": "reverse",
                      "text": "UPX 加壳 脱壳 逆向" }) + "\n",
        encoding="utf-8",
    )
    idx = WriteupIndex()
    n = idx.load_corpus_jsonl(str(p))
    assert n == 2
    hits = idx.retrieve("RSA 费马分解 p q 接近", k=1)
    assert len(hits) == 1
    assert hits[0]["id"] == "w1"
    # 返回字段完整
    for key in ("id", "score", "title", "category", "tags", "text", "source"):
        assert key in hits[0]


def test_skills_ingestion_loads_docs():
    idx = WriteupIndex()
    n = idx.load_skills_docs(limit=5)
    assert n > 0
    # 检索到的 skill 文档带 source 标记
    idx.build()
    hits = idx.retrieve("rsa", k=3)
    assert any(h["id"].startswith("skill:") for h in hits)


# ── 混合嵌入重排（伪 embed_fn 验证融合逻辑）──
def test_hybrid_embedding_breaks_bm25_tie():
    idx = WriteupIndex()
    idx.add_doc("a", "xxx", {})
    idx.add_doc("b", "yyy", {})
    idx.build()
    # BM25 两篇都 0 分 -> 平局，按文档顺序 a 在前
    assert idx.retrieve("zzz", k=2, embed_fn=None)[0]["id"] == "a"

    def emb(s):
        return [1.0] if s.strip() in ("yyy", "zzz") else [0.0]

    hy = idx.retrieve("zzz", k=2, embed_fn=emb, alpha=0.5)
    # 嵌入将 b(yyy) 与查询(zzz)判为最相似 -> 重排后 b 居首
    assert hy[0]["id"] == "b"


def test_hybrid_embedding_failure_falls_back_to_bm25():
    idx = WriteupIndex()
    idx.add_doc("a", "alpha beta", {})
    idx.add_doc("b", "gamma delta", {})
    idx.build()

    def emb(_s):
        raise RuntimeError("embedding service down")

    # embed_fn 抛异常应静默降级为 BM25-only，不崩溃
    hy = idx.retrieve("alpha", k=2, embed_fn=emb)
    assert hy[0]["id"] == "a"


# ── prompts 知识注入块 ──
class _Q:
    title = "RSA 费马分解题目"
    category = "crypto"
    description = ""
    attachments = None
    flag_pattern = "flag"
    extra = {}


def _ctx_with_hits(hits):
    ctx = AgentContext(question=_Q())
    ctx.knowledge_hits = hits
    ctx.few_shot = False
    return ctx


def test_prompts_injects_knowledge_block():
    hits = [{"title": "RSA 费马分解", "category": "crypto",
             "text": "RSA 因式分解 费马 p q 接近"}]
    prompt = build_plan_prompt(_ctx_with_hits(hits), 0)
    assert "检索到的历史解法" in prompt
    assert "RSA 费马分解" in prompt


def test_prompts_no_knowledge_block_when_empty():
    prompt = build_plan_prompt(_ctx_with_hits(None), 0)
    assert "检索到的历史解法" not in prompt


# ── env 闸（默认关 = 零回归）──
def test_env_gating_off_returns_none(monkeypatch):
    monkeypatch.delenv("CTF_AGENT_WRITEUP_RAG", raising=False)
    from core import main_agent as M
    agent = M.MainAgent.__new__(M.MainAgent)
    assert agent._get_knowledge_index() is None


def test_env_gating_on_builds_index(monkeypatch):
    monkeypatch.setenv("CTF_AGENT_WRITEUP_RAG", "1")
    from core import main_agent as M
    agent = M.MainAgent.__new__(M.MainAgent)
    idx = agent._get_knowledge_index()
    assert idx is not None
    # 真实语料 + skills 已纳入
    assert len(idx.meta) > 20
    # 检索可用
    assert idx.retrieve("UPX 脱壳", k=1)[0]["id"] == "reverse-upx"
