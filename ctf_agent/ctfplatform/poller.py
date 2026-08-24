"""平台轮询模块（抄 verialabs/ctf-agent：长轮询实时拉题 → 自动提交）。

核心能力（对应 verialabs CTFd 对接）：
- 定时拉取题目列表（自定义间隔，默认 30s）
- 去重：只处理新出现的题目（记录已处理 ID）
- 对新题：创建实例 → 获取访问信息 → 调用 solver 解题 → 提交 flag
- 容错：Token 失效/429 限流由平台客户端 _request 自动重试；单题失败不阻塞轮询
- 审计：处理历史可查询（答辩可追溯）

用法（测试赛当天）：
    poller = PlatformPoller(platform=DasCTFPlatform(), solver=solver)
    await poller.run_once()          # 手动跑一轮
    await poller.run_forever(30)     # 定时轮询
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

from ctfplatform.base import ChallengeInfo, PlatformAPI, SubmitResult

# solver 类型：callable(challenge_info) -> dict（含 flag 字段）
SolverFn = Callable[[ChallengeInfo], Awaitable[dict]]


@dataclass
class PollRecord:
    """单题的轮询处理记录（审计可追溯）。"""

    challenge_id: str
    title: str
    category: str
    started_at: float = 0.0
    finished_at: float = 0.0
    flag: str = ""
    submitted: bool = False
    accepted: bool = False
    detail: str = ""
    error: str = ""
    extra_candidates: list = field(default_factory=list)  # 2026-08-22 锐评：多候选提交迭代

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "title": self.title,
            "category": self.category,
            "duration_s": round(self.finished_at - self.started_at, 1),
            "flag": self.flag,
            "submitted": self.submitted,
            "accepted": self.accepted,
            "detail": self.detail,
            "error": self.error,
            "candidates": self.extra_candidates[:5],
        }


class PlatformPoller:
    """平台轮询器：定时拉题 → 去重 → 解题 → 提交。"""

    def __init__(
        self,
        platform: PlatformAPI,
        solver: Optional[SolverFn] = None,
        submit_after_solve: bool = True,
        max_retry_submit: int = 2,
        use_shared_progress: bool = True,
        solve_timeout: float = 900.0,  # 单题解题硬超时（默认 15min，防一题卡死阻塞整场）
    ) -> None:
        """
        Args:
            platform: 平台客户端（DasCTFPlatform 等）
            solver: 可选 callable(challenge_info) -> dict（含 flag）；None 时只拉题不解题
            submit_after_solve: 解出后自动提交 flag
            max_retry_submit: 提交失败重试次数
            use_shared_progress: 启用跨会话共享进度（防重复攻坚）
            solve_timeout: 单题 solver 硬超时（秒），防一题卡死阻塞整场轮询
        """
        self.platform = platform
        self.solver = solver
        self.submit_after_solve = submit_after_solve
        self.max_retry_submit = max_retry_submit
        self.solve_timeout = solve_timeout
        # 跨题并发上限（架构 A4 修复：此前 getattr(self,"max_concurrency") 永远 None
        # → run_once 硬编码 or 2，配置不生效；现由 env 可调，默认仍 2 保稳）
        self.max_concurrency = max(1, int(os.getenv("CTF_AGENT_MAX_CONCURRENCY", "2")))
        self._processed: set[str] = set()      # 已处理题目 ID（去重）
        self._records: dict[str, PollRecord] = {}  # 审计记录
        # P0-4 修复（2026-08-21 赛后）：失败题重试队列——瞬时 429/详情拉取失败
        # 的题不永久丢弃，延迟 2-5 分钟再试，最多 3 次。{id: {"attempts": n, "next_retry_at": ts, "ch": ch}}
        self._retry_queue: dict[str, dict] = {}
        self.RETRY_MAX_ATTEMPTS = 3
        self.RETRY_DELAY_BASE = 120.0   # 首延迟 2 分钟；逐次 ×1.5 封顶 5 分钟
        # 提交次数熔断（锐评 P0：防幻觉耗光 50 次/题额度）
        self._submit_counts: dict[str, dict] = {}  # id -> {"total": n, "consec_fail": n}
        self.SUBMIT_FUSE_TOTAL = 30      # 累计 30 次提交 → 暂停
        self.SUBMIT_FUSE_CONSEC = 5      # 连续 5 次失败 → 暂停
        # 靶机槽位准入控制（锐评核心约束：每队 3 靶机上限——需要靶机的题并发 ≤3，
        # 简单题已按难度排序先启动，先到先得槽位，防开局拥塞占死靶机）
        self._instance_slots = asyncio.Semaphore(3)
        # 提交串行化锁（决赛建议 3.1：竞速多 provider 并发解出时统一走此通道，
        # 题目粒度锁防双提交 + 熔断——收敛 solver 内部直接 submit_flag）
        self._submit_locks: dict[str, asyncio.Lock] = {}
        # 跨会话共享进度（P0-1：防重复攻坚）
        if use_shared_progress:
            try:
                from core.progress import get_progress
                self._progress = get_progress()
            except Exception as exc:  # noqa: BLE001 - 进度模块故障不阻塞解题
                logger.warning("共享进度模块加载失败: %s", exc)
                self._progress = None
        else:
            self._progress = None

    # ── 对外 API ────────────────────────────────────────

    async def run_once(self, ignore_processed: bool = True) -> list[PollRecord]:
        """执行一轮：拉题 → 对未处理的新题解题/提交。

        Args:
            ignore_processed: True=跳过已处理题（默认）；False=全部重跑（重试场景）

        Returns:
            本轮处理的记录列表
        """
        challenges = await self.platform.list_challenges()
        new_ones = []
        now = time.monotonic()
        for ch in challenges:
            if ignore_processed and ch.id in self._processed:
                continue
            # 跨会话共享进度（P0-1）：已解则跳过
            if self._progress is not None and self._progress.is_solved(ch.id):
                self._processed.add(ch.id)
                logger.info("[%s] %s 已被其他会话解出，跳过拉题", ch.id, ch.title)
                continue
            # P0-4 修复（2026-08-21 赛后）：失败题重试队列——未到重试时间/已耗尽
            # 重试次数的题本轮跳过；到点才重新处理（不再"处理前即入 processed 永久丢题"）。
            rq = self._retry_queue.get(ch.id)
            if rq is not None:
                if rq["attempts"] >= self.RETRY_MAX_ATTEMPTS:
                    logger.info("[%s] 重试 %d 次仍失败，放弃该题", ch.id, rq["attempts"])
                    self._processed.add(ch.id)
                    self._retry_queue.pop(ch.id, None)
                    continue
                if now < rq["next_retry_at"]:
                    continue  # 未到重试时间
                rq["attempts"] += 1  # 本轮到点重试
                logger.info("[%s] 失败题重试（第 %d/%d 次）", ch.id, rq["attempts"],
                            self.RETRY_MAX_ATTEMPTS)
            new_ones.append(ch)
        if not new_ones:
            logger.info("轮询：无新题（累计已处理 %d 题，重试队列 %d 题）",
                        len(self._processed), len(self._retry_queue))
            return []

        logger.info("轮询：发现 %d 道新题", len(new_ones))
        # 新题优先抢一血：按难度排序（VERY_EASY 优先——最简单新题先启动，抢分更快）
        try:
            from scripts._scan_firstblood import _rank

            new_ones.sort(key=_rank)
        except Exception:  # noqa: BLE001 - 排序失败不影响并发抢
            pass
        # 跨题并发（提速：多题并行解题，受 max_concurrency 限制防 LLM 限流）
        max_conc = getattr(self, "max_concurrency", None) or 2
        sem = asyncio.Semaphore(max_conc)

        async def _limited(ch):
            async with sem:
                return await self._handle_challenge(ch)

        results = await asyncio.gather(*[_limited(ch) for ch in new_ones])
        # P0-4 修复（2026-08-21 赛后）：处理后分类——
        # 成功/有数据尽力解 → 入 processed；详情拉取失败/无数据（瞬时 429）→
        # 进重试队列（延迟 2-5 分钟，最多 3 次），不再"处理前即 processed 永久丢题"。
        now = time.monotonic()
        for ch, rec in zip(new_ones, results):
            if rec is None:
                continue
            if rec.accepted or rec.flag or (rec.error and rec.error not in ("skipped_no_data", "detail_fetch_failed")):
                # 已解出/提交成功/其他确定性失败（数据存在但解不出）→ 不再重试
                self._processed.add(ch.id)
                self._retry_queue.pop(ch.id, None)
                continue
            if rec.error in ("skipped_no_data", "detail_fetch_failed"):
                # 瞬时故障（详情拉取失败/无数据）→ 延迟重试
                rq = self._retry_queue.get(ch.id)
                if rq is None:
                    rq = {"attempts": 0, "next_retry_at": 0.0, "ch": ch}
                rq["attempts"] += 1
                _delay = min(self.RETRY_DELAY_BASE * (1.5 ** (rq["attempts"] - 1)), 300.0)
                rq["next_retry_at"] = now + _delay
                self._retry_queue[ch.id] = rq
                logger.info("[%s] %s（%s）→ 进重试队列（第 %d/%d 次，%.0fs 后再试）",
                            ch.id, rec.error, rec.detail[:40], rq["attempts"],
                            self.RETRY_MAX_ATTEMPTS, _delay)
                continue
            self._processed.add(ch.id)
        return results

    async def run_forever(self, interval: float = 30.0, max_rounds: int = 0,
                          fast_interval: float = 0.0, fast_duration: float = 120.0) -> list[PollRecord]:
        """定时轮询（比赛主循环）。

        Args:
            interval: 轮询间隔秒数（默认 30s）
            max_rounds: 最大轮数；0=无限（Ctrl+C 退出）
            fast_interval: 高频窗口间隔（>0 启用；启动后 fast_duration 秒内用此间隔，
                           抢开局/整点放题一血——锐评：新题检测延迟是失分点）
            fast_duration: 高频窗口持续时间秒（默认 120s）

        P0 数据链路修复（2026-08-21，429 轮询风暴 + 403 WAF 封禁）：
        - fast_interval 下限钳制 30s：赛时 3s 高频轮询导致 37 次/轮 429
          + 触发平台 403 WAF 风控（初赛 0 解出根因），下限提到 30s 双保险
        - 连续 429 → 阶梯退避（30/60/120/300s，platform.backoff_suggestion 提供）
        - 403 WAF 命中 → 冷却期内间隔拉到 300s（platform.waf_blocked() 提供）
        - 列表请求失败 + 连续空轮 → 间隔倍增（上限 300s）；成功/有新题即回落
        """
        if fast_interval > 0 and fast_interval < 30.0:
            logger.warning("fast_interval %.1fs 过激进（<30s），钳制到 30s 防 429/403 WAF",
                           fast_interval)
            fast_interval = 30.0
        logger.info("开始定时轮询（间隔 %.0fs%s）", interval,
                    f"，高频窗口 {fast_interval:.0f}s×{fast_duration:.0f}s" if fast_interval > 0 else "")
        import time as _time

        start = _time.time()
        round_no = 0
        all_records: list[PollRecord] = []
        empty_streak = 0
        while max_rounds == 0 or round_no < max_rounds:
            round_no += 1
            try:
                records = await self.run_once()
                all_records.extend(records)
            except Exception as exc:  # noqa: BLE001 - 单轮异常不阻塞轮询
                logger.warning("轮询第 %d 轮异常: %s", round_no, exc)
                records = []
            # 高频窗口内用 fast_interval（新题检测更快，抢一血；下限 5s 防 429）
            cur_interval = interval
            if fast_interval > 0 and (_time.time() - start) < fast_duration:
                cur_interval = fast_interval
            # 连续 429 阶梯退避（platform 层计数，请求成功自动回落；
            # 返回值 >0 才覆盖当前间隔，避免误伤放题高频窗口）
            _sugg = getattr(self.platform, "backoff_suggestion", None)
            if _sugg is not None:
                try:
                    _s = float(_sugg(interval))
                    if _s > 0:
                        cur_interval = max(cur_interval, _s)
                except Exception:  # noqa: BLE001 - 退避建议异常不阻塞
                    pass
            # 403 WAF 冷却退避（P0 修复 2026-08-21：初赛 3s 高频轮询触发平台
            # 「疑似攻击行为」403 封禁的教训——封禁期内轮询拉到 300s 不打扰平台）
            _waf = getattr(self.platform, "waf_blocked", None)
            if _waf is not None:
                try:
                    _w = float(_waf())
                    if _w > 0:
                        cur_interval = max(cur_interval, 300.0)
                        logger.warning("WAF 风控冷却中（剩余 %.0fs），轮询退避至 300s", _w)
                except Exception:  # noqa: BLE001 - 冷却查询异常不阻塞
                    pass
            # 列表请求失败 + 连续空轮 → 间隔倍增（上限 300s）
            _ok = getattr(self.platform, "last_list_ok", None)
            if records:
                empty_streak = 0
            elif _ok is not None and not _ok():
                empty_streak += 1
                cur_interval = min(300.0, cur_interval * 2)
            else:
                empty_streak = 0
            if empty_streak and empty_streak % 5 == 0:
                logger.warning("轮询连续 %d 轮无新题且列表请求失败，退避至 %.0fs",
                               empty_streak, cur_interval)
            await asyncio.sleep(cur_interval)
        return all_records

    # ── 内部实现 ────────────────────────────────────────

    async def _handle_challenge(self, ch: ChallengeInfo) -> PollRecord:
        """处理单题：创建实例 → 解题 → 提交（各步独立容错）。"""
        rec = PollRecord(
            challenge_id=ch.id,
            title=ch.title,
            category=ch.category,
            started_at=time.time(),
        )
        self._records[ch.id] = rec
        # ── 跨会话共享进度（P0-1：已解则跳过，防重复攻坚）──
        if self._progress is not None:
            if self._progress.is_solved(ch.id):
                rec.flag = self._progress.get_flag(ch.id)
                rec.accepted = True
                rec.submitted = True
                rec.detail = "skip_solved_by_other_session"
                rec.finished_at = time.time()
                logger.info("[%s] %s 已被其他会话解出，跳过", ch.id, ch.title)
                return rec
            self._progress.mark_attempted(ch.id, title=ch.title, category=ch.category)
        # ── P0 修复（2026-08-21 正式赛）：列表接口 description/endpoints 缺失，
        #    必须先 get_challenge 补全详情（含靶机地址/真实题面），否则 agent 拿到
        #    空题面只能纯推理空转 → 全部 stuck_loop。──
        try:
            detail = await self.platform.get_challenge(ch.id)
            if detail is not None:
                # P0 修复（2026-08-21）：详情 description 权威覆盖——_parse_challenge
                # 可能对空题面回退到标题（如 "rabbit encryption"），若仍用
                # "if not ch.description" 条件则真实题面永远合并不进去（回归 0 解出）。
                _dd = getattr(detail, "description", "") or ""
                if _dd and _dd != getattr(ch, "title", ""):
                    ch.description = _dd
                _dextra = dict(getattr(detail, "extra", None) or {})
                _cextra = dict(getattr(ch, "extra", None) or {})
                # 合并详情里更完整的字段（endpoints/attachment/difficulty/description）
                for _k in ("endpoints", "attachment", "difficulty", "description", "score", "flag_format"):
                    if _dextra.get(_k) is not None:
                        _cextra[_k] = _dextra[_k]
                ch.extra = _cextra
                # ── P0 修复（2026-08-21 正式赛）：has_attachment/has_instance
                #    必须按详情判定——列表接口恒 False，附件在 extra.attachment.url
                #    （如 10793/10732/10734），不修则附件永不下载，crypto/misc 空转。──
                _att = _cextra.get("attachment") or _cextra.get("attachments")
                _has_att = bool(
                    getattr(detail, "has_attachment", False)
                    or (isinstance(_att, dict) and bool(_att.get("url")))
                    or (isinstance(_att, list) and bool(_att))
                )
                if _has_att:
                    ch.has_attachment = True
                if getattr(detail, "has_instance", False):
                    ch.has_instance = True
        except Exception as _exc:  # noqa: BLE001 - 详情补全失败不阻塞主流程
            logger.warning("[%s] get_challenge 详情补全失败: %s", ch.id, _exc)
            # P0-4 修复（2026-08-21 赛后）：详情拉取失败（多为 429/5xx）标记，
            # 下游据此走"detail_fetch_failed"进重试队列，而非误判"无数据永久跳过"。
            try:
                ch.extra = dict(getattr(ch, "extra", None) or {})
                ch.extra["_detail_fetch_failed"] = True
            except Exception:  # noqa: BLE001
                pass
            _detail_fetch_failed = True
        else:
            _detail_fetch_failed = False
        # ── 数据可达率观测（P0 数据链路修复 2026-08-21）──
        # 每题记录 desc/附件/靶机是否可达，赛后按此统计"数据可达率"——
        # 数据可达是解出率的前提，先于一切推理质量指标。
        _cextra = ch.extra or {}
        logger.info(
            "[数据可达] %s desc=%d字 att=%s endpoints=%d has_instance=%s",
            ch.id, len(getattr(ch, "description", "") or ""),
            bool(getattr(ch, "has_attachment", False)),
            len(_cextra.get("endpoints") or []) if isinstance(_cextra.get("endpoints"), list) else 0,
            bool(getattr(ch, "has_instance", False)),
        )
        # ── P0-4（复盘补遗 2026-08-21）：无数据即止损，禁止空转 ──
        # 题面空 + 无附件 + 无靶机（无 endpoints）→ 直接跳过 LLM 循环，砍掉 87% 无效流量。
        _has_endpoints = bool((ch.extra or {}).get("endpoints"))
        if (not getattr(ch, "description", "")) and (not getattr(ch, "has_attachment", False)) \
                and (not getattr(ch, "has_instance", False)) and (not _has_endpoints):
            # P0-4 修复（2026-08-21 赛后）：区分"详情拉取失败（瞬时 429，可重试）"
            # 与"真实无数据"——前者进重试队列，不永久丢题。
            if _detail_fetch_failed:
                rec.error = "detail_fetch_failed"
                rec.detail = "详情拉取失败（瞬时限流/5xx，稍后重试）"
            else:
                rec.error = "skipped_no_data"
                rec.detail = "无解题数据（题面空+无附件+无靶机）"
            logger.info("[%s] %s 无解题数据，跳过（P0-4 止损: %s）", ch.id, ch.title, rec.error)
            rec.finished_at = time.time()
            return rec
        try:
            flag = ""
            _instance_created = False
            try:
                if ch.has_instance:
                    # 靶机槽位准入：创建+解题都在槽位内（实例占用期间不超 3——
                    # 压测暴露：原只包创建不包解题，解题期间实例可超 3）
                    async with self._instance_slots:
                        inst = await self.platform.create_instance(ch.id)
                        if inst.instance_id:
                            _instance_created = True
                            # P0修复（2026-08-21）：实例创建后强制刷新detail缓存，
                            # 拿最新endpoints（避免缓存中是启动前的空值）
                            try:
                                if hasattr(self.platform, "_detail_cache"):
                                    self.platform._detail_cache.pop(str(ch.id), None)
                            except Exception:  # noqa: BLE001
                                pass
                            # 重新拉详情并更新access
                            _new_detail = await self.platform.get_challenge(ch.id)
                            if _new_detail is not None:
                                _dextra = dict(getattr(_new_detail, "extra", None) or {})
                                _cextra = dict(ch.extra or {})
                                for _k in ("endpoints", "attachment", "attachments"):
                                    if _dextra.get(_k) is not None:
                                        _cextra[_k] = _dextra[_k]
                                ch.extra = _cextra
                            access = await self.platform.get_access(inst.instance_id, challenge_id=ch.id)
                            # 把访问信息挂到 extra，供 solver/描述补充
                            ch.extra = {**(ch.extra or {}), "access": access.__dict__}
                        flag, _cands = await self._solve_challenge(ch)
                        if _cands:
                            rec.extra_candidates = _cands
                else:
                    flag, _cands = await self._solve_challenge(ch)
                    if _cands:
                        rec.extra_candidates = _cands
            finally:
                # P0修复（2026-08-21）：无论解题成功/失败/超时，必须销毁实例，
                # 否则平台3个靶机槽位占满后后续所有题无靶机可用
                if _instance_created and ch.has_instance:
                    try:
                        await self.platform.destroy_instance(ch.id)
                        logger.debug("[%s] 靶机实例已回收", ch.id)
                    except Exception as _de:  # noqa: BLE001
                        logger.warning("[%s] 靶机实例回收失败: %s", ch.id, _de)
            rec.flag = flag
            # 3. 提交（可选）——提交前格式校验（架构 A1：幻觉/乱码 flag 不直提，
            #    否则每发幻觉都烧 1 次提交额度；熔断只兜底事后，拦不住第一发）
            flag = self._validate_flag(ch, flag)
            rec.flag = flag
            if flag and self.submit_after_solve:
                # 2026-08-22 锐评「提交迭代」：多候选依次提交（非猜测）——
                # 主 flag 置首 + presolve 多候选（flag_extract_guard 提取，
                # 含 ROT13 变体）逐候选提交，_submit_with_retry 内部按列表迭代。
                _submit_flags = [flag]
                for _c in (rec.extra_candidates or []):
                    _cv = self._validate_flag(ch, _c)
                    if _cv and _cv not in _submit_flags:
                        _submit_flags.append(_cv)
                rec.submitted, rec.accepted, rec.detail = await self._submit_with_retry(
                    ch.id, _submit_flags)
                # 提交成功后写回共享进度（P0-1：跨会话可见）
                if rec.accepted and self._progress is not None:
                    self._progress.mark_solved(
                        ch.id, flag=flag, note=f"{ch.title}({ch.category})",
                    )
                    logger.info("[%s] %s 已解出并写入共享进度", ch.id, ch.title)
                # 提交成功后本地落盘兜底（锐评 P0：防 Agent 崩溃丢已解 flag——手动提交兜底）
                if rec.accepted:
                    self._persist_submitted(ch, flag)
            logger.info("[%s] %s 处理完成 flag=%s accepted=%s",
                        ch.id, ch.title, flag or "(未解出)", rec.accepted)
        except Exception as exc:  # noqa: BLE001 - 单题失败不拖垮轮询
            rec.error = str(exc)[:200]
            logger.warning("[%s] 处理异常: %s", ch.id, exc)
        rec.finished_at = time.time()
        return rec

    def _validate_flag(self, ch, flag: str) -> str:
        """提交前 flag 校验（架构 A1 修复：幻觉/乱码 flag 不直提）。

        黑名单式保守拦截（避免误杀平台自定义格式）：
        - 空/仅空白 → 拦
        - 长度 >256 或含空白字符 → 拦（真实 flag 无空格，幻觉/拼接乱码常含）
        - 题目声明 flag_format 时：先按格式校验，不匹配再兜底标准
          flag{...}/DASCTF{...}；两者都不过 → 拦
        """
        flag = (flag or "").strip()
        if not flag:
            return ""
        if len(flag) > 256 or any(c.isspace() for c in flag):
            logger.warning("[%s] flag 校验拦截（空白/超长，疑似幻觉）: %r",
                           getattr(ch, "id", "?"), flag[:40])
            return ""
        # 可打印 ASCII 检查：真实 flag 全为可打印 ASCII；\x80-\xff 乱码
        # 正是 LLM 幻觉拼接（如 reverse_upx 的 bffab...\x91\xe6\xff\xff）的形态
        if any(ord(c) < 0x20 or ord(c) > 0x7e for c in flag):
            logger.warning("[%s] flag 校验拦截（含非可打印字符，疑似幻觉）: %r",
                           getattr(ch, "id", "?"), flag[:40])
            return ""
        fmt = str(getattr(ch, "flag_format", "") or "").strip()
        if fmt:
            ok = None
            try:
                ok = re.fullmatch(fmt, flag)
            except re.error:
                ok = None
            if not ok:
                try:
                    ok = re.fullmatch(r"(?:flag|DASCTF)\{[^}\s]{4,}\}", flag)
                except re.error:
                    ok = None
            if not ok:
                logger.warning("[%s] flag 格式校验拦截（疑似幻觉）: %r (fmt=%r)",
                               getattr(ch, "id", "?"), flag[:40], fmt)
                return ""
        return flag

    async def _solve_challenge(self, ch) -> tuple:
        """解题（单题硬超时保护，分级超时——供槽位内外共用）。

        2026-08-22 锐评「提交迭代」修复：返回 (flag, candidates)——
        solver 输出带 candidates（presolve 多候选提取透传）时，提交环节
        逐候选迭代（非猜测——flag_extract_guard 多候选依次提交）。
        """
        flag = ""
        candidates: list = []
        if self.solver is not None:
            try:
                out = await asyncio.wait_for(
                    self.solver(ch), timeout=self._timeout_for(ch)
                )
            except asyncio.TimeoutError:
                logger.warning("[%s] %s 单题解题超时 %.0fs，跳过该题",
                               ch.id, ch.title, self._timeout_for(ch))
                out = {"flag": "", "error": {"category": "timeout",
                        "detail": f"单题解题超时 {self.solve_timeout:.0f}s"}}
            flag = str(out.get("flag") or "")
            # 多候选透传（提交迭代）：solver 的 candidates 去重 + 主 flag 置首
            cands = out.get("candidates") or []
            if isinstance(cands, (list, tuple)):
                for c in cands:
                    _c = str(c or "").strip()
                    if _c and _c not in candidates:
                        candidates.append(_c)
            if flag and flag not in candidates:
                candidates.insert(0, flag)
        return flag, candidates

    async def submit_serialized(self, challenge_id: str, flag: str) -> tuple[bool, bool, str]:
        """带锁串行提交（决赛建议 3.1：竞速多 provider 并发解出时统一走此通道，
        题目粒度锁防双提交 + _submit_with_retry 熔断保护）。

        收敛：solver 内部/抢一血脚本的直接 submit_flag → 改调本方法。
        """
        lock = self._submit_locks.setdefault(challenge_id, asyncio.Lock())
        async with lock:
            flags = flag if isinstance(flag, (list, tuple)) else [flag]
            return await self._submit_with_retry(challenge_id, flags)

    async def _submit_with_retry(self, challenge_id: str, flags) -> tuple[bool, bool, str]:
        """提交 flag（重试至熔断阈值——压测暴露：原 max_retry_submit=2 提前退出，
        连续失败到不了阈值 5，熔断永不触发；改为循环直到连续5/累计30 才停）。

        熔断规则：累计提交 ≥30 或连续失败（flag 错误）≥5 → 暂停该题自动提交（标记人工审核）。
        第⑥层修复（复盘补遗 2026-08-21）：提交请求层故障（网络/HTTP/鉴权，request_failed）
        不计入 consec_fail（那是针对 flag 错误），避免正确 flag 因平台抖动被静默丢弃（10719 教训）。
        """
        st = self._submit_counts.setdefault(challenge_id, {"total": 0, "consec_fail": 0, "req_fail": 0})
        # 熔断检查：已超阈值则不再自动提交
        if st["total"] >= self.SUBMIT_FUSE_TOTAL or st["consec_fail"] >= self.SUBMIT_FUSE_CONSEC:
            logger.warning("[%s] 提交熔断触发（累计 %d/连续失败 %d）——暂停自动提交，标记人工审核",
                           challenge_id, st["total"], st["consec_fail"])
            return True, False, f"submit_fused(total={st['total']},consec={st['consec_fail']})"
        attempt = 0
        while (st["total"] < self.SUBMIT_FUSE_TOTAL
               and st["consec_fail"] < self.SUBMIT_FUSE_CONSEC):
            # 锐评修复（2026-08-22）：多候选迭代——flag 错误时换下一个候选
            # （非猜测——flag_extract_guard 多候选依次提交——accepted 即停）
            if isinstance(flags, (list, tuple)) and flags:
                flag = flags[attempt % len(flags)]
            result: SubmitResult = await self.platform.submit_flag(challenge_id, flag)
            st["total"] += 1
            if result.accepted:
                st["consec_fail"] = 0  # 成功后重置连续失败
                return True, True, result.detail
            if result.request_failed:
                # 第⑥层修复：提交请求层故障（非 flag 错误）——不计入 consec_fail，
                # 用更长退避重试，避免正确 flag 在平台限流/5xx 抖动时被熔断丢弃。
                st["req_fail"] += 1
                logger.warning("[%s] 提交请求故障（非 flag 错误，第 %d 次）: %s",
                               challenge_id, st["req_fail"], result.detail)
                if st["req_fail"] >= self.SUBMIT_FUSE_TOTAL:
                    logger.warning("[%s] 提交请求故障熔断（累计 %d，非 flag 错误，标记人工审核）",
                                   challenge_id, st["req_fail"])
                    return True, False, f"submit_req_fused(req_fail={st['req_fail']})"
                attempt += 1
                await asyncio.sleep(min(2.0 * (attempt + 1), 8.0))
                continue
            # 正常响应但 flag 错误：计入连续失败（现有熔断逻辑）
            st["consec_fail"] += 1
            logger.warning("[%s] 提交未通过（flag 错误，第 %d 次, 累计 %d）: %s",
                           challenge_id, attempt + 1, st["total"], result.detail)
            # 熔断：连续失败达标立即停
            if st["consec_fail"] >= self.SUBMIT_FUSE_CONSEC or st["total"] >= self.SUBMIT_FUSE_TOTAL:
                logger.warning("[%s] 提交熔断（连续失败 %d/累计 %d）——暂停该题自动提交",
                               challenge_id, st["consec_fail"], st["total"])
                return True, False, f"submit_fused(total={st['total']},consec={st['consec_fail']})"
            attempt += 1
            await asyncio.sleep(min(1.0 * (attempt + 1), 5.0))
        return True, False, f"submit_fused(total={st['total']},consec={st['consec_fail']})"

    def _timeout_for(self, ch) -> float:
        """分级硬超时（锐评：简单题 10min/中等 20min/难题 30min——防卡题浪费后面快题时间）。"""
        diff = str((getattr(ch, "extra", None) or {}).get("difficulty", "")).upper()
        if diff in ("VERY_EASY", "EASY"):
            return 600.0   # 简单题 10min（快题优先收割）
        if diff in ("MEDIUM",):
            return 1200.0  # 中等题 20min
        if diff in ("HARD", "VERY_HARD"):
            return 1800.0  # 难题 30min
        return self.solve_timeout  # 未知难度用默认（900s）

    def _persist_submitted(self, ch, flag: str) -> None:
        """提交成功本地落盘兜底（锐评 P0：防 Agent 崩溃丢已解 flag——手动提交兜底）。

        写 data/results/submitted_flags.json（追加记录：题目/flag/时间）。
        """
        import json
        import os

        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "data", "results", "submitted_flags.json")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            recs = []
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    recs = json.load(f)
            recs.append({
                "challenge_id": str(getattr(ch, "id", "")),
                "title": str(getattr(ch, "title", "")),
                "category": str(getattr(ch, "category", "")),
                "flag": str(flag),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            with open(path, "w", encoding="utf-8") as f:
                json.dump(recs, f, ensure_ascii=False, indent=1)
        except Exception as exc:  # noqa: BLE001 - 落盘失败不阻塞主流程
            logger.warning("[%s] 本地落盘失败: %s", getattr(ch, "id", "?"), exc)

    # ── 审计查询 ────────────────────────────────────────

    def records(self) -> list[dict]:
        """全部处理记录（Web 面板/答辩展示）。"""
        return [r.to_dict() for r in self._records.values()]

    def summary(self) -> dict:
        """轮询汇总：已处理/解出/提交成功数。"""
        records = list(self._records.values())
        return {
            "processed": len(records),
            "solved": sum(1 for r in records if r.flag),
            "accepted": sum(1 for r in records if r.accepted),
            "failed": sum(1 for r in records if r.error),
        }
