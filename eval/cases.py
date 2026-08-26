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
            category=str(data.get("category", "misc")),
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
        """正确性判定：明文比对（flag 为明文时）或 sha256 比对（flag 为占位时）。"""
        if not candidate:
            return False
        if self.flag_is_placeholder:
            exp = self.expected_sha256
            if not exp:
                return False
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
        if q.flag:
            out[q.id] = q.flag
    return out
