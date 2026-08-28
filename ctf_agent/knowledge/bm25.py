"""零依赖 BM25 实现（Okapi BM25，确定性、可单测）。

Tokenizer 同时覆盖：英文/代码 token（[a-z0-9_]+）与中文单字（CJK），
因此对中英文混合的 CTF 技术文档都有效，无需 jieba 等外部分词。
"""

import math
import re
from collections import defaultdict

_TOKEN_RE = re.compile(r"[a-z0-9_]+|[一-鿿]")


def tokenize(text: str):
    if not text:
        return []
    return _TOKEN_RE.findall(text.lower())


class BM25:
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.docs = []          # list[list[str]] —— 每篇的 token 序列
        self.doc_ids = []       # list[str]
        self.doc_lens = []      # list[int]
        self.df = defaultdict(int)
        self.idf = {}
        self.avgdl = 0.0
        self._built = False

    # ── 索引构建 ──
    def add(self, doc_id: str, tokens: list):
        self.docs.append(tokens)
        self.doc_ids.append(doc_id)
        self.doc_lens.append(len(tokens))
        for t in set(tokens):
            self.df[t] += 1
        self._built = False

    def build(self):
        n = len(self.docs)
        self.avgdl = (sum(self.doc_lens) / n) if n else 0.0
        for t, df in self.df.items():
            # 标准 idf（加 0.5 平滑，避免 df 接近 n 时为负）
            self.idf[t] = math.log(1 + (n - df + 0.5) / (df + 0.5))
        self._built = True

    # ── 打分 ──
    def score(self, query_tokens: list, doc_idx: int) -> float:
        if not self._built:
            self.build()
        dl = self.doc_lens[doc_idx]
        freq = {}
        for t in self.docs[doc_idx]:
            freq[t] = freq.get(t, 0) + 1
        s = 0.0
        for qt in set(query_tokens):
            idf = self.idf.get(qt)
            if not idf:
                continue
            f = freq.get(qt, 0)
            if f == 0:
                continue
            s += idf * (f * (self.k1 + 1)) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s

    def search(self, query_tokens: list, top_k: int = 5):
        if not self._built:
            self.build()
        scored = [(self.score(query_tokens, i), self.doc_ids[i])
                  for i in range(len(self.docs))]
        scored.sort(reverse=True)
        return [(s, did) for s, did in scored[:top_k]]
