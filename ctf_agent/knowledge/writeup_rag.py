"""Writeup RAG 检索核心（IDEA-5 务实落地）。

知识库 = 项目自有真实资产：
  - knowledge/writeups_corpus.jsonl：12 道已验证解法的技术文档 + 精选 skill 用法
  - skills/ 全部 skill 文档（可选纳入，load_skills_docs）

检索策略：
  - 默认 BM25-only（零依赖、离线、确定性）。
  - 传入 embed_fn（callable: str -> list[float]）即启用混合重排：
        hybrid = (1-alpha)*norm(bm25) + alpha*norm(cosine)
    真实环境可注入 sentence_transformers / 自托管 embedding；无模型时自动降级。
"""

import glob
import json
import math
import os
import re

from .bm25 import BM25, tokenize

SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "skills")
CORPUS_PATH = os.path.join(os.path.dirname(__file__), "writeups_corpus.jsonl")


def _cosine(a, b):
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _norm(vals):
    if not vals:
        return []
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1.0
    return [(v - lo) / rng for v in vals]


class WriteupIndex:
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.bm25 = BM25(k1, b)
        self.meta = {}          # doc_id -> {title, category, tags, text, tools, source, ...}
        self._built = False

    # ── 语料加载 ──
    def add_doc(self, doc_id: str, text: str, meta: dict = None):
        meta = dict(meta or {})
        meta["text"] = text
        self.meta[doc_id] = meta
        self.bm25.add(doc_id, tokenize(text))
        self._built = False

    def load_corpus_jsonl(self, path: str = CORPUS_PATH) -> int:
        if not os.path.exists(path):
            return 0
        n = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                doc_id = d.get("id") or f"doc{n}"
                text = d.get("text", "")
                rest = {k: v for k, v in d.items() if k not in ("id", "text")}
                self.add_doc(doc_id, text, rest)
                n += 1
        return n

    def load_skills_docs(self, skills_dir: str = SKILLS_DIR, limit: int = 0) -> int:
        """把 skills/*.py 模块 docstring 纳入语料（真实工具手册）。"""
        if not os.path.isdir(skills_dir):
            return 0
        n = 0
        for py in sorted(glob.glob(os.path.join(skills_dir, "*.py"))):
            name = os.path.splitext(os.path.basename(py))[0]
            if name == "__init__":
                continue
            text = self._extract_skill_doc(py)
            if not text:
                continue
            self.add_doc(
                f"skill:{name}", text,
                {"title": name, "category": "tool",
                 "tags": ["skill", name], "source": "skills/" + os.path.basename(py)},
            )
            n += 1
            if limit and n >= limit:
                break
        return n

    @staticmethod
    def _extract_skill_doc(py_path: str) -> str:
        try:
            src = open(py_path, encoding="utf-8").read()
        except OSError:
            return ""
        m = re.search(r'"""(.*?)"""', src, re.S)
        doc = m.group(1).strip() if m else ""
        return doc[:1500]

    def build(self):
        self.bm25.build()
        self._built = True

    # ── 检索 ──
    def retrieve(self, query: str, k: int = 5, embed_fn=None, alpha: float = 0.3) -> list:
        if not self._built:
            self.build()
        q_tokens = tokenize(query)
        bm25_scores = [self.bm25.score(q_tokens, i) for i in range(len(self.bm25.docs))]
        bm25_n = _norm(bm25_scores)

        if embed_fn is not None:
            try:
                qe = embed_fn(query)
                des = [embed_fn(self.meta[self.bm25.doc_ids[i]]["text"])
                       for i in range(len(self.bm25.docs))]
                cos = [_cosine(qe, d) for d in des]
                cos_n = _norm(cos)
                hybrid = [(1 - alpha) * b + alpha * c for b, c in zip(bm25_n, cos_n)]
            except Exception:
                hybrid = bm25_n
        else:
            hybrid = bm25_n

        ranked = sorted(range(len(hybrid)), key=lambda i: hybrid[i], reverse=True)[:k]
        out = []
        for i in ranked:
            did = self.bm25.doc_ids[i]
            m = self.meta[did]
            out.append({
                "id": did,
                "score": round(hybrid[i], 4),
                "title": m.get("title", did),
                "category": m.get("category", ""),
                "tags": m.get("tags", []),
                "text": m.get("text", "")[:600],
                "source": m.get("source", ""),
            })
        return out
