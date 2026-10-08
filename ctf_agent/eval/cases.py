"""本地测试题库加载器（复用 Security-Agent evaluation 思想）。

题库目录结构：
    data/questions/<category>/<question_id>.json

每个题目 JSON 结构：
{
  "id": "crypto-001",            # 唯一 id（mock 预置答案主键）
  "category": "crypto",          # web/crypto/misc/reverse/pwn
  "title": "RSA 共模攻击",
  "description": "题目描述（给 LLM 的输入）",
  "flag": "flag{...}",           # 官方 flag（本地题库才有；评测用）
  "flag_pattern": "flag\\{[^}]+\\}",   # 可选，默认 flag{...}
  "attachments": ["data/questions/crypto/001/pub.pem"],  # 可选附件路径
  "difficulty": "easy"           # easy/medium/hard（本地标注用）
}
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 真 flag 红线（2026-08-24）：题库 JSON 不再存明文 flag，只存 flag_sha256 占位。
# 当 flag 字段是 64 位十六进制 sha256 时，视为「占位预期值」，评测时把解出 flag
# 算 sha256 与之比对——既保持本地自检自洽，又保证明文 flag 永不进 git 历史。
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# 规范类别集（权威来源：scripts/ingest_external_ctf.py 的 VALID_CATS）。
# 外部题源（NYU/CSAW、cybench 等）会产出别名拼写，如 rev（逆向）、forensics（取证）。
# 若不在加载层归一化，下游按 `== "reverse"` / `in ("crypto","pwn","reverse")` 硬判的
# presolve 路由、兜底链、heavy 模型升级、步数预算会对这些题**全部失效**——即
# 「能力存在但不可达」的系统性缺口（2026-10-07 实测：41 道外部题受影响）。
CANONICAL_CATEGORIES = ("web", "crypto", "misc", "reverse", "pwn")

# 别名 → 规范类别。forensics→misc 与本地库把取证题（如 real_misc_longjian*_forensics*）
# 标为 misc 的既有约定一致；反向映射 rev→reverse 与 scripts/fetch_google_ctf.py 的
# CAT_MAP 同向。未列出的类别原样返回（不猜测，保留可观测性）。
_CATEGORY_ALIASES = {
    "rev": "reverse",
    "reversing": "reverse",
    "reverse-engineering": "reverse",
    "reverse_engineering": "reverse",
    "forensics": "misc",
    "forensic": "misc",
}


def normalize_category(raw: object) -> str:
    """把外部题源的各种类别拼写归一化到规范集。

    - 去空白 / 转小写；
    - 命中别名表则映射（rev→reverse、forensics→misc）；
    - 空值按既有默认回落 misc；
    - 未知类别原样返回，不静默改写（便于观测新题源）。
    """
    cat = str(raw or "").strip().lower()
    if not cat:
        return "misc"
    return _CATEGORY_ALIASES.get(cat, cat)


@dataclass
class Question:
    """一道 CTF 题目的统一描述（本地题库/官方 API 共用结构）。"""

    id: str
    title: str
    category: str = "misc"        # web/crypto/misc/reverse/pwn
    description: str = ""
    flag: Optional[str] = None     # 本地题库标注的官方 flag（评测用）
    flag_pattern: str = r"flag\{[^}]+\}"
    # 真 flag 红线（2026-08-24）：明文 flag 不得入 git；题库只存 flag_sha256 占位。
    flag_sha256: Optional[str] = None
    attachments: list = field(default_factory=list)
    difficulty: str = "easy"
    # 溯源口径（2026-08-24 诚实化整改）：real_past_ctf=历年真实赛题（外部真值，唯一 KPI 分母）；
    # self_authored_training=自产教学/靶场题（不计分）。benchmark 按此字段拆分解出率。
    provenance: str = "self_authored_training"
    # O1 联动（2026-08-21）：extra 承载平台附加元信息（difficulty/score/access 等），
    # main_agent 读 extra.difficulty 做分级墙钟与高难题首步重型升级。
    extra: dict = field(default_factory=dict)
    # 评测护栏（2026-08-21 去作弊化收尾）：answer_disclosed=True 表示该题附件
    # 曾自带 flag 明文（教学简化题），不参与解出率统计——防止本地水位虚高。
    answer_disclosed: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Question":
        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "")),
            category=normalize_category(data.get("category", "misc")),
            description=str(data.get("description", "")),
            flag=data.get("flag"),
            flag_sha256=data.get("flag_sha256"),
            flag_pattern=str(data.get("flag_pattern", r"flag\{[^}]+\}")),
            attachments=list(data.get("attachments", [])),
            difficulty=str(data.get("difficulty", "easy")),
            provenance=str(data.get("provenance", "self_authored_training")),
            extra=dict(data.get("extra", {}) or {}),
            answer_disclosed=bool(data.get("answer_disclosed", False)),
        )

    def to_prompt_text(self) -> str:
        """生成给 LLM 的题目描述文本。"""
        parts = [f"题目: {self.title}"]
        if self.description:
            parts.append(self.description)
        if self.attachments:
            parts.append(f"附件: {', '.join(self.attachments)}")
        parts.append(f"flag 格式: {self.flag_pattern}")
        return "\n".join(parts)

    @property
    def flag_is_placeholder(self) -> bool:
        """flag 字段是 sha256 占位（真 flag 红线：明文已迁出 git）。"""
        return bool(self.flag) and bool(_SHA256_RE.match(str(self.flag)))

    @property
    def expected_sha256(self) -> Optional[str]:
        """评测预期值的 sha256：优先 flag_sha256 字段，其次 flag 本身是占位 sha256。"""
        if self.flag_sha256 and _SHA256_RE.match(str(self.flag_sha256)):
            return str(self.flag_sha256).lower()
        if self.flag_is_placeholder:
            return str(self.flag).lower()
        return None

    def flag_matches(self, candidate: Optional[str]) -> bool:
        """正确性判定：有 sha256 预期值则 sha256 比对，否则明文比对。

        2026-10-08 修复：原实现把「走哪条分支」gate 在 `flag_is_placeholder`
        （要求 `flag` 字段**本身**是 sha256 串），于是第三种合法形态
        「`flag=None` + 只有 `flag_sha256`」（外部题全部如此，全库去重实测 40 题）
        落进明文分支、与 `None` 比对 → **恒 False**：正确答案被自己的验证器判
        hallucination（`run.py:387` 生产判分正走此路径）。改为直接取
        `expected_sha256`（其优先级「flag_sha256 字段 > flag 占位」已由本类定义），
        三种形态全覆盖：flag 明文（无 sha256）/ flag=sha256 占位 / flag=None+flag_sha256。
        形态分布（去重源库）：`(None,set)=40（全在 questions_external）/ (sha256,set)=122 /
        (plain,none)=57 / (None,none)=1 / (plain,set)=0` —— `(plain,set)=0` 保证本次改动
        对未来题库无行为变更。（⚠️ 初稿曾记「79 题」：那把派生副本 heldout_run 与源库
        重复计入，去重后 40。）"""
        if not candidate:
            return False
        exp = self.expected_sha256
        if exp:
            import hashlib
            return hashlib.sha256(str(candidate).encode("utf-8")).hexdigest() == exp
        return str(candidate) == str(self.flag)


def _in_answers_dir(att: str) -> bool:
    """附件路径是否位于答案键目录 data/answers 下（路径级判定，不看文件名——
    真题挑战文件可以合法叫 flag.txt，答案键只按目录归属剔除）。"""
    norm = str(att).replace("\\", "/").lower()
    return norm.startswith("data/answers/") or "/data/answers/" in norm


def load_questions(questions_dir: str = "data/questions",
                   include_disclosed: bool = False) -> list[Question]:
    """加载题库目录下全部题目（按 category 子目录递归）。

    评测护栏（去作弊化收尾）：
    - answer_disclosed=True 的题目（附件曾自带 flag 明文的教学题）默认排除，
      include_disclosed=True 才载入——防止解出率虚高；
    - 位于 data/answers 答案键目录的附件一律剔除并告警，
      即使被误挂进题目 JSON 也进不了解题链路（真题自带 flag.txt 不受影响）。
    """
    base = Path(questions_dir)
    if not base.is_dir():
        logger.warning("题库目录不存在: %s", base)
        return []

    questions: list[Question] = []
    skipped_disclosed = 0
    for json_file in sorted(base.rglob("*.json")):
        # 2026-09-30 修复：跳过附件目录——附件里可能存在 .json 输入文件
        # （如 collusion 题的 bobs-key.json/carols-key.json/message.json），
        # 会被 rglob 误当题目 JSON 解析，污染题库（misc 虚增 2→5）。
        # 只扫题目 JSON，附件只由题目 JSON 的 attachments 字段显式引用。
        _rel_parts = {p.lower() for p in json_file.relative_to(base).parts[:-1]}
        if _rel_parts & {"_attachments", "answers", "_answers", "_keys", "_solutions"}:
            continue
        try:
            with open(json_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            q = Question.from_dict(data)
            # 题目 id 默认用文件名（无 id 字段时）
            if not q.id:
                q.id = json_file.stem
            if q.answer_disclosed and not include_disclosed:
                skipped_disclosed += 1
                continue
            # 答案键防泄漏护栏：data/answers 下的附件不得进入解题链路
            clean_atts = [a for a in q.attachments if not _in_answers_dir(a)]
            if len(clean_atts) != len(q.attachments):
                logger.warning("[%s] 剔除答案键附件: %s", q.id,
                               sorted(set(q.attachments) - set(clean_atts)))
                q.attachments = clean_atts
            questions.append(q)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("跳过无法解析的题库文件 %s: %s", json_file, exc)
    if skipped_disclosed:
        logger.info("已排除 %d 道 answer_disclosed 题（include_disclosed=True 可载入）",
                    skipped_disclosed)
    return questions


def load_by_category(category: str, questions_dir: str = "data/questions",
                     include_disclosed: bool = False) -> list[Question]:
    """按题型过滤加载。"""
    return [q for q in load_questions(questions_dir, include_disclosed=include_disclosed)
            if q.category == category]


def preset_answers(questions: list[Question]) -> dict[str, str]:
    """从题目列表提取 {id: 预期值} 预置答案表（注入 mock / 本地校验）。

    2026-08-24 真 flag 红线：flag 为 sha256 占位时，预置值即该 sha256——
    mock 模式（禁止引用）下不会误命中明文；本地真实评测改走 flag_matches 比对。
    """
    out = {}
    for q in questions:
        # 2026-09-30 防御：mock/轻量 Question 可能无 flag 属性，getattr 兜底
        # （run.py:477 等调用点现在对任意 question 对象传 preset_answers([q])）。
        if getattr(q, "flag", None):
            out[q.id] = q.flag
    return out
