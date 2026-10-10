"""答案密钥隔离（ITEM4-A，2026-10-10）。

ITEM4-A 纪律：`flag`/`flag_sha256` 字段仅作评分真值；`flag.txt`/`answer.txt`/
`*.txt` 等答案类附件 **严禁进入 solver**（presolve 与 LLM 主链都不喂）。这些
附件内容即明文真值（sha256 == 题面 flag_sha256），喂给 solver 等于把答案直接
塞进候选，属欺诈性注水（历史 fix A 已被 revert，见 commit 2ca7f39）。

本模块是 presolve 与 main_agent / action_executor / fallbacks / phases / prompts
共用的隔离入口：

- `is_answer_key_attachment(question, path)`：文件内容（归一化后）sha256 命中题面
  真值 → 是答案密钥（内容级判定，防改名绕过）；文件名命中答案词干仅作「无法用
  内容证伪时」的兜底剔除。
- `filter_answer_key_attachments(question, paths)`：剔除命中项，返回真实输入。

设计要点（证据先行，见 `.workbuddy/tmp/verify_answers.py` 实测）：
- real_* 题库 65 个 `flag.txt` 中 64 个是真值（内容归一化后 sha256 == flag_sha256），
  1 个（`real_crypto_anwang_crypto1`）是**八进制密文输入**（解码后才是 flag），
  属合法输入——不能按文件名一刀切，否则会删掉可解的输入文件。
  故**内容级匹配为权威判据**，文件名仅兜底。

fail-closed：任何异常都按「非答案密钥」返回，宁漏不误删真实输入。
"""

import hashlib
import os

# 答案密钥词干（basename 去掉 .txt/.json 等扩展名后命中即视为「疑似答案文件名」）。
# 仅作兜底：当无法用内容证伪（无 flag_sha256 / 文件缺失或超大）时才据此剔除。
_ANSWER_KEY_WORDS = {
    "flag", "answer", "solution", "key", "secret",
}

# 内容校验读取上限（字节）。答案文件必小；超此不读，避免拖慢。
_MAX_ANSWER_KEY_BYTES = 1 << 20  # 1 MiB


def _is_sha256_hex(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in v
    )


def _answer_sha256_candidates(question) -> set:
    """题面声明的真值 sha256 候选集合（小写 hex，64 位）。"""
    cands: set = set()
    for attr in ("expected_sha256", "flag_sha256"):
        v = getattr(question, attr, None)
        if _is_sha256_hex(v):
            cands.add(v.lower())
    # 兼容 dict 式 question（测试 / 兜底）
    extra = getattr(question, "extra", None) or {}
    if isinstance(extra, dict):
        for k in ("expected_sha256", "flag_sha256"):
            v = extra.get(k)
            if _is_sha256_hex(v):
                cands.add(v.lower())
    return cands


def _normalized_hashes(raw: bytes) -> set:
    """文件内容及其常见归一化形式的 sha256 集合（用于与真值比对）。

    覆盖：原始字节 / 去首尾空白（答案常带 \\r\\n）/ 八进制序列解码后
    （anwang 类 octal 输入，解码文本身≠答案，故不会误命中 → 正确保留为输入）。
    """
    hs = set()
    hs.add(hashlib.sha256(raw).hexdigest())
    hs.add(hashlib.sha256(raw.strip()).hexdigest())
    try:
        txt = raw.decode("utf-8", "ignore").strip()
        toks = txt.replace("\r", " ").replace("\n", " ").split()
        if toks and all(t.strip().isdigit() for t in toks):
            dec = bytes(int(t, 8) for t in toks)
            hs.add(hashlib.sha256(dec).hexdigest())
            hs.add(hashlib.sha256(dec.strip()).hexdigest())
    except Exception:  # noqa: BLE001
        pass
    return hs


def _content_verdict(question, path, cands) -> "bool | None":
    """内容是否等于答案真值。

    返回：
    - True  ：内容归一化后 sha256 命中真值 → 确为答案密钥；
    - False ：文件可读且内容哈希不命中 → 内容级可证伪为非答案（必须保留）；
    - None  ：无法判定（无候选 / 文件缺失或超大）→ 交由文件名兜底。
    """
    try:
        if not (cands and os.path.isfile(path)):
            return None
        sz = os.path.getsize(path)
    except OSError:
        return None
    if sz == 0 or sz > _MAX_ANSWER_KEY_BYTES:
        return None
    try:
        raw = open(path, "rb").read()
    except OSError:
        return None
    if _normalized_hashes(raw) & cands:
        return True
    # 文件可读但哈希不命中 → 确认不是答案（内容级证伪）
    return False


def is_answer_key_attachment(question, path) -> bool:
    """path 是否应被隔离为答案密钥附件。

    判定优先级：
    ① 内容级（权威，防改名）：内容归一化后 sha256 命中真值 → 剔除；
       内容可读却未命中 → 保留（即使是 flag.txt 也是合法输入，如 anwang octal）。
    ② 文件名级（兜底）：仅当内容无法证伪（无真值/文件缺失或超大）且文件名命中
       答案词干时才剔除。

    fail-closed：任何异常都按「非答案密钥」返回 False（宁漏不误删真实输入）。
    """
    try:
        if not path:
            return False
        cands = _answer_sha256_candidates(question)
        base = os.path.basename(str(path)).lower()
        stem = base
        for suf in (".txt", ".json", ".log", ".md", ".text"):
            if stem.endswith(suf):
                stem = stem[: -len(suf)]
                break
        name_is_answer = stem in _ANSWER_KEY_WORDS

        verdict = _content_verdict(question, path, cands)
        if verdict is True:
            return True
        if verdict is False:
            # 内容已证伪为非答案：即使文件名像答案也保留（合法输入）
            return False
        # 内容无法判定：仅当文件名命中答案词干才保守剔除
        return name_is_answer
    except Exception:  # noqa: BLE001 - fail-closed
        return False


def filter_answer_key_attachments(question, paths) -> list:
    """剔除 paths 中的答案密钥附件，返回剩余（真实输入）路径列表。"""
    if not paths:
        return []
    return [p for p in paths if not is_answer_key_attachment(question, p)]


class _DictQuestion:
    """dict 式 question 适配（benchmark_heldout 等读原始 JSON 的场景）。

    仅暴露过滤器读取的属性（flag / flag_sha256 / expected_sha256 / extra），
    使内容级判定可直接复用，无需把整个 Question 对象搬进扫描器。
    """

    def __init__(self, d: dict):
        self.flag = d.get("flag")
        self.flag_sha256 = d.get("flag_sha256")
        self.expected_sha256 = None
        self.extra = d.get("extra") or {}


def is_answer_key_only(qdict: dict) -> bool:
    """题的所有附件是否都是答案密钥（剔除后无真实输入）→ 即 KNOWN_LEAK。

    用于 ITEM4-B：把「题面唯一附件即答案」的题从能力分母中显式标记排除。
    内容级判定（归一化 sha256 命中真值），与 `_attachments` 过滤器同源，保证
    anwang 类八进制密文输入（命名 flag.txt 但内容≠答案）**不**被误判为泄露。
    """
    atts = qdict.get("attachments") or []
    if not atts:
        return False
    return not filter_answer_key_attachments(_DictQuestion(qdict), atts)
