# -*- coding: utf-8 -*-
"""P0 附件/靶机注入 harness（2026-11-11 从 run.py 抽出，可单测）。

把原本嵌在 ``run.py:build_platform_solver.solver`` 闭包里的
「详情补全 + 附件下载落地 + 靶机注入」逻辑抽成可复用、可单测的独立模块，
并补上 HARDENING_BACKLOG P0 要求的**求解前结构化早退门禁**：

    「无附件且无靶机时直接结构化早退，不进入推理。」

设计原则（与既有代码一致，fail-open，绝不因平台抖动而空转或崩溃）：
- 任何平台调用失败都不抛异常 → 降级为「该项输入缺失」；
- **不依赖 poller 是否预填 access**：harness 自己调 ``platform.get_access``
  取真实靶机，杜绝 ``ch.extra["access"]`` 未预填导致靶机永不注入的死链；
- 产出与 ``eval.cases.Question`` 完全兼容，``main_agent.solve`` 直接可用；
- 可选 ``should_early_exit``：调用方在 ``core(question)`` 之前检查，
  无解输入则直接跳过，省下整轮 LLM 推理（呼应 main_agent.py:1131 的
  crypto/misc 无数据快速放弃，但提前到求解入口而非烧 2 步后才停）。

集成点（run.py 可改为调用本模块，降低回归风险）：
    question, inv = await prepare_question(platform, ch, cache_dir)
    if inv.should_early_exit()[0]:
        return {"task_status": "skipped_no_data", "early_exit": inv.should_early_exit()[1]}
    return await core(question, 0, None)
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# 详情补全失败后的重试等待（秒）。测试可传 0 避免真实 sleep。
_DETAIL_RETRY_SLEEP = 2.0


@dataclass
class InputInventory:
    """一道题可用的「求解输入」清单（结构化，供早退决策与 prompt 注入）。"""

    challenge_id: str = ""
    has_attachment: bool = False
    attachment_paths: list = field(default_factory=list)  # 本地已下载路径
    has_target: bool = False
    targets: list = field(default_factory=list)           # 靶机地址串（host:port / url）
    detail_fetch_failed: bool = False
    notes: list = field(default_factory=list)

    def has_solvable_input(self) -> bool:
        """是否有任何真实输入（附件或靶机）可供取证。"""
        return self.has_attachment or self.has_target

    def should_early_exit(self) -> tuple[bool, str]:
        """backlog P0：无附件且无靶机 → 结构化早退，不进入推理。

        Returns:
            (True, reason)  —— 应早退；reason 为 ``no_attachment_no_target``
            (False, "")     —— 有输入，可进入求解
        """
        if not self.has_attachment and not self.has_target:
            return True, "no_attachment_no_target"
        return False, ""


async def _download_attachment(platform, url: str, cache_dir: str) -> str:
    """下载单个附件到 cache_dir，返回本地路径（失败返回空串）。

    复用平台客户端鉴权头下载（避免 403）；已存在且非空则直接复用。
    逻辑对齐 run.py:_download。
    """
    try:
        name = os.path.basename(urlparse(url).path) or f"att_{abs(hash(url))}.bin"
        local = os.path.join(cache_dir, name)
        if os.path.exists(local) and os.path.getsize(local) > 0:
            return local
        if hasattr(platform, "download_attachment_bytes"):
            content = await platform.download_attachment_bytes(url)
        else:  # 兜底：自立 httpx 客户端（带 token 鉴权头）
            import httpx

            headers = {}
            token = getattr(platform, "token", "")
            auth_header = getattr(platform, "auth_header", "Authorization")
            if token:
                headers[auth_header] = token
            async with httpx.AsyncClient(timeout=60, follow_redirects=True,
                                         trust_env=False) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                content = resp.content
        if content:
            with open(local, "wb") as fh:
                fh.write(content)
            logger.info("附件已下载: %s (%d B)", name, len(content))
            return local
    except Exception as exc:  # noqa: BLE001 - 附件下载失败不阻塞解题
        logger.warning("附件下载失败 %s: %s", url, exc)
    return ""


async def _ensure_detail(platform, ch, retry_sleep: float = _DETAIL_RETRY_SLEEP
                         ) -> tuple[dict, bool]:
    """补全题目详情（get_challenge），返回 (extra_dict, detail_fetch_failed)。

    对齐 run.py solver 入口逻辑：列表接口只给 {id,name,...} 无 endpoints/attachment，
    详情失败（多为 429）则重试一次，仍失败才标记 _detail_fetch_failed，
    交由下游早退，避免一枪毙命式空转。
    """
    try:
        _detail = await platform.get_challenge(ch.id)
        if _detail is None or not getattr(_detail, "extra", None):
            if retry_sleep:
                await asyncio.sleep(retry_sleep)
            _detail = await platform.get_challenge(ch.id)
        if _detail is not None:
            _dextra = dict(getattr(_detail, "extra", None) or {})
            _cextra = dict(getattr(ch, "extra", None) or {})
            for _k in ("endpoints", "attachment", "attachments", "difficulty",
                       "description", "score", "flag_format"):
                if _dextra.get(_k) is not None:
                    _cextra[_k] = _dextra[_k]
            # 同步布尔属性（列表阶段恒 False，须从 detail 更新）
            if getattr(_detail, "has_attachment", False):
                ch.has_attachment = True
            if getattr(_detail, "has_instance", False):
                ch.has_instance = True
            _dd = getattr(_detail, "description", "") or ""
            if _dd and _dd != getattr(ch, "title", ""):
                ch.description = _dd
            if not getattr(ch, "flag_format", "") and getattr(_detail, "flag_format", ""):
                ch.flag_format = _detail.flag_format
            return _cextra, False
    except Exception as _e:  # noqa: BLE001 - 补全失败不阻塞解题
        logger.warning("[%s] solver 入口 get_challenge 补全失败: %s",
                       getattr(ch, "id", "?"), _e)

    # 补全失败：仅当 ch 确实无任何真实数据时才标记 _detail_fetch_failed，
    # 不得用"拉详情失败"覆盖 poller/前一帧已补全的真实数据。
    ch.extra = dict(getattr(ch, "extra", None) or {})
    _has_real = bool(
        ch.extra.get("endpoints")
        or ch.extra.get("attachment") or ch.extra.get("attachments")
        or getattr(ch, "description", "")
    )
    if not _has_real:
        ch.extra["_detail_fetch_failed"] = True
        return ch.extra, True
    return ch.extra, False


async def prepare_question(platform, ch, cache_dir: str = "data/platform_downloads",
                           question_cls=None,
                           retry_sleep: float = _DETAIL_RETRY_SLEEP) -> tuple[Any, InputInventory]:
    """平台 ChallengeInfo → 富化 Question + InputInventory。

    Args:
        platform: 实现 ``get_challenge`` / ``download_attachment`` /
            ``download_attachment_bytes`` / ``get_access`` 的平台对象
            （DasCTFPlatform 或测试用 FakePlatform）。
        ch: ChallengeInfo（须含 id/title/category/description/flag_format/
            has_attachment/has_instance/extra 属性）。
        cache_dir: 附件本地缓存目录（相对 ctf_agent/ 或绝对路径）。
        question_cls: 可注入自定义 Question 类（测试用）；默认 eval.cases.Question。

    Returns:
        (question, inventory)
    """
    from eval.cases import Question  # 延迟导入，避免测试循环依赖

    _Question = question_cls or Question
    os.makedirs(cache_dir, exist_ok=True)

    extra, detail_failed = await _ensure_detail(platform, ch, retry_sleep=retry_sleep)

    # ── 附件下载（平台 URL → 本地缓存；失败不阻塞）──
    attachment_paths: list[str] = []
    if getattr(ch, "has_attachment", False):
        urls = await platform.download_attachment(ch.id)
        for u in (urls or []):
            p = await _download_attachment(platform, str(u), cache_dir)
            if p:
                attachment_paths.append(p)

    # ── 靶机：显式调 get_access（不依赖 poller 预填 access）──
    targets: list[str] = []
    try:
        access = await platform.get_access(ch.id, challenge_id=ch.id)
        if access is not None:
            _host = getattr(access, "host", "") or ""
            _port = getattr(access, "port", 0) or 0
            _url = getattr(access, "url", "") or ""
            if _host:
                targets.append(f"host={_host}" + (f":{_port}" if _port else ""))
            if _url:
                targets.append(f"url={_url}")
    except Exception as _aexc:  # noqa: BLE001
        logger.warning("[%s] get_access 失败（靶机缺失）: %s",
                       getattr(ch, "id", "?"), _aexc)

    # 合并 endpoints 提取的靶机（web/pwn 常见 exposeIps/proxyIps）
    try:
        from scripts._scan_firstblood import _extract_targets

        for t in (_extract_targets(extra or {}) or []):
            if t not in targets:
                targets.append(t)
    except Exception:  # noqa: BLE001 - 靶机注入失败不阻塞
        pass

    # ── 构造 Question（镜像 run.py:939）──
    question = _Question(
        id=ch.id,
        title=ch.title,
        category=ch.category,
        description=str(getattr(ch, "description", "") or ""),
        flag_pattern=getattr(ch, "flag_format", None) or r"flag\{[^}]+\}",
        difficulty=str((extra or {}).get("difficulty", "")),
        extra={"difficulty": (extra or {}).get("difficulty", ""),
               "platform_meta": extra or {}},
    )
    question.attachments = attachment_paths
    if targets:
        question.extra["targets"] = targets
        if "靶机" not in question.description:
            question.description = (
                (question.description + "\n" if question.description else "")
                + "靶机地址: " + " ".join(targets)
            )
        question.description = (
            (question.description + "\n" if question.description else "")
            + "[靶机访问] " + " ".join(targets)
        )

    inventory = InputInventory(
        challenge_id=ch.id,
        has_attachment=bool(attachment_paths),
        attachment_paths=attachment_paths,
        has_target=bool(targets),
        targets=targets,
        detail_fetch_failed=detail_failed,
    )
    return question, inventory


def build_injection_prompt(inventory: InputInventory, question: Any) -> str:
    """生成结构化上下文注入串（供 main_agent plan prompt 追加，或解题前日志）。

    仅在有真实输入时返回非空串；无解输入返回空（由 should_early_exit 处理）。
    """
    if not inventory.has_solvable_input():
        return ""
    lines = ["【本题可用输入】"]
    if inventory.attachment_paths:
        lines.append("- 附件（已下载本地，可用 file_analyze / script 处理）：")
        for p in inventory.attachment_paths:
            lines.append(f"  · {p}")
    if inventory.targets:
        lines.append(f"- 靶机地址：{' '.join(inventory.targets)}")
    lines.append("请优先基于上述真实输入取证，禁止纯推理猜 flag。")
    return "\n".join(lines)
