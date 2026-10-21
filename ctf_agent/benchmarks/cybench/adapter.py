"""Cybench 适配器（T2 阶段 A 脚手架，2026-10-22）。

把 Cybench 形态的题目 JSON 加载为仓库统一的 eval.cases.Question 模型，使其能接入
eval.benchmark.run_benchmark 的「加载→求解→评分→报告」全链路。

Cybench 题目形态（与 eval.cases.Question 高度兼容，仅多了 source_pool、附件路径
指向 data/questions_ext_cybench/_attachments）：
    {
      "id": "ext_cybench_xxx",
      "category": "crypto",
      "title": "Cybench crypto permuted",
      "description": "…",
      "flag_sha256": "<hex>",          # 评测预期值
      "flag": "<同 hex，占位>",         # 真 flag 红线：明文不进 git
      "flag_pattern": "…",
      "attachments": ["data/questions_ext_cybench/_attachments/…"],
      "difficulty": "MEDIUM",
      "source_pool": "questions_ext_cybench"
    }

真实 Cybench 任务需 Docker 容器化评测（每题一个容器）；本脚手架的 dry-run 不依赖
Docker / 密钥 / 网络，只验证数据通路（加载 + 评分 + 报告）。真实链路见 runner.dry_run
的 --real 模式与未来的容器执行器。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Sequence

from eval.cases import Question

logger = logging.getLogger(__name__)

# Cybench 来源判定：source_pool 含此串 → 真实历年赛题（real_past_ctf）；
# 文件名含此串 → 同样视为 Cybench 题目（external_unseen 落地的 ext_cybench_*，
# 以及本脚手架的 cybench_sample_* 合成样本均命中）。
_CYBENCH_MARK = "cybench"


def _provenance_for(data: dict) -> str:
    """Cybench 来源按真实赛题计（real_past_ctf）；其余回落 JSON 自带或默认训练题。"""
    existing = data.get("provenance")
    if existing:
        return str(existing)
    pool = str(data.get("source_pool", "")).lower()
    if _CYBENCH_MARK in pool:
        return "real_past_ctf"
    return "self_authored_training"


def cybench_question_from_dict(data: dict) -> Question:
    """把单条 Cybench 题目 dict 转成统一 Question（保留 source_pool 到 extra）。"""
    q = Question.from_dict({
        "id": data.get("id"),
        "title": data.get("title", ""),
        "category": data.get("category", "misc"),
        "description": data.get("description", ""),
        "flag": data.get("flag"),
        "flag_sha256": data.get("flag_sha256"),
        "flag_pattern": data.get("flag_pattern", r"flag\{[^}]+\}"),
        "attachments": list(data.get("attachments", []) or []),
        "difficulty": str(data.get("difficulty", "easy")),
        "provenance": _provenance_for(data),
    })
    q.extra = dict(data.get("extra", {}) or {})
    q.extra.setdefault("source_pool", data.get("source_pool", ""))
    return q


def _is_attachment_dir(parts: Sequence[str]) -> bool:
    """路径段是否落在附件/答案目录（与 eval.cases.load_questions 同口径）。"""
    lowered = {str(p).lower() for p in parts}
    return bool(lowered & {"_attachments", "answers", "_answers", "_keys", "_solutions"})


def load_cybench_questions(sources: Sequence[str | Path]) -> list[Question]:
    """从文件 / 目录 / glob 加载 Cybench 题目。

    sources 每个元素可以是：
      - 单个 .json 文件；
      - 含题目 JSON 的目录（递归 rglob *.json）；
      - glob 表达式（如 benchmarks/external_unseen/questions/ext_cybench_*.json）。

    仅加载 Cybench 来源（source_pool 含 cybench，或文件名含 ext_cybench），其余
    同目录的清单/基线/非 Cybench 题目自动跳过；附件/答案子目录不作为题目解析。
    """
    files: list[Path] = []
    for src in sources:
        p = Path(src)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.json")))
        elif any(ch in str(src) for ch in "*?["):
            files.extend(sorted(Path(".").glob(str(src))))
        elif p.is_file():
            files.append(p)

    questions: list[Question] = []
    skipped = 0
    for f in files:
        if _is_attachment_dir(f.parts):
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("[cybench] 跳过无法解析: %s: %s", f, exc)
            skipped += 1
            continue
        if not isinstance(data, dict) or not data.get("id"):
            continue  # 清单/基线等非题目 JSON
        pool = str(data.get("source_pool", "")).lower()
        if _CYBENCH_MARK not in pool and _CYBENCH_MARK not in str(f.name).lower():
            continue  # 非 Cybench 题目
        questions.append(cybench_question_from_dict(data))

    logger.info("[cybench] 加载 %d 题（跳过 %d 非 Cybench/无法解析）", len(questions), skipped)
    return questions
