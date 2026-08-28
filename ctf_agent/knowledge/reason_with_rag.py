"""writeup_rag 推理层（IDEA-派生产物）。

把「检索相关 writeup」与「调用 LLM 推理」串成一条可验证链路：
  问题文本 -> BM25 检索 top-k writeup -> 组装 prompt -> LLM 产出解题脚本/思路
  ->（由调用方执行脚本并核对 flag）-> 真实验证 LLM 是否真能推理出解。

设计原则：本模块只负责「检索 + 组装 + 调 LLM」，不替 LLM 作弊（不注入答案）。
LLM 的贡献 = 基于检索到的 writeup 方法，结合题目参数，写出可运行的解题代码。
"""

import asyncio
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge.writeup_rag import WriteupIndex
from core.llm_wrapper import llm_text

SYSTEM = """你是一名资深 CTF 密码学/逆向解题专家。用户会提供与本题相似的历年 CTF writeup 作为参考，
以及一道具体题目的参数。请基于参考 writeup 的解题思路，结合题目参数，编写一段**可直接运行的 Python 脚本**
（仅用标准库 / sympy / gmpy2），求解该题并 print 出最终 flag（格式 DASCTF{...}）。
只输出代码，用 ```python 围栏包裹，不要任何解释性文字。"""


def build_index(load_skills: bool = False) -> WriteupIndex:
    idx = WriteupIndex()
    idx.load_corpus_jsonl()
    if load_skills:
        idx.load_skills_docs()
    idx.build()
    return idx


def reason_with_rag(problem_text: str, k: int = 3, llm_client=None, load_skills: bool = False):
    """检索相关 writeup 并请 LLM 基于它们推理。

    返回 (llm_response: str, retrieved_docs: list)。
    """
    idx = build_index(load_skills)
    docs = idx.retrieve(problem_text, k=k)
    context = "\n\n".join(
        f"### 参考 writeup：{d['title']}\n{d['text']}" for d in docs
    )
    user = (
        f"以下是相关的 CTF writeup 参考：\n\n{context}\n\n"
        f"### 本题题目\n{problem_text}\n\n请编写 Python 解题脚本："
    )
    resp = asyncio.run(llm_text(SYSTEM, user, 0, llm_client=llm_client))
    return resp, docs


def extract_code(text: str, lang: str = "python") -> str:
    """从 LLM 回复中抽取代码块。"""
    m = re.search(r"```" + lang + r"\s*(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    m = re.search(r"```(.*?)```", text, re.S)
    return m.group(1).strip() if m else ""
