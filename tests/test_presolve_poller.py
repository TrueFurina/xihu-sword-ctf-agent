# -*- coding: utf-8 -*-
"""P1-3/P0-4 回归测试：PreSolve 统一层去重 + poller 失败题重试（2026-08-21 赛后）。

覆盖：
1. presolve：同一附件只嗅探一次（per-question 标记，并发去重）
2. presolve：answers 提供时命中必须匹配本地答案（不匹配丢弃）
3. poller：详情拉取失败（detail_fetch_failed）的题不永久丢——进重试队列可重试
"""

import asyncio
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── 假注册表（统计 flag_scan/crypto_auto 调用次数）──────────────


class FakeRegistry:
    def __init__(self):
        self.calls = {"flag_scan": 0, "crypto_auto": 0}

    def has(self, name):
        return name in ("flag_scan", "crypto_auto")

    async def run(self, name, params):
        self.calls[name] += 1
        out = type("Out", (), {"ok": True, "text": "flag{test_presolve_dedup}"})()
        return out


def _question(attachments=("x.txt",), category="crypto", description=""):
    class Q:
        id = "q1"
        title = "t"
    q = Q()
    q.category = category
    q.description = description
    q.attachments = list(attachments)
    q.difficulty = "easy"
    q.flag_pattern = r"flag\{[^}]+\}"
    q.extra = {}
    return q


def test_presolve_dedup_same_attachment_sniffed_once():
    """同一附件只嗅探一次：第二次调用 presolve 直接返回 None，不重复嗅探。"""
    from core.presolve import presolve

    registry = FakeRegistry()
    q = _question(attachments=["a.txt"], category="crypto")

    async def main():
        # 第一次：flag_scan 命中 → 返回 flag
        flag1 = await presolve(q, registry=registry, answers=None)
        # 第二次：已标记 → 不再嗅探
        flag2 = await presolve(q, registry=registry, answers=None)
        # 第三次 force=True：强制重扫仍命中
        flag3 = await presolve(q, registry=registry, answers=None, force=True)
        return flag1, flag2, flag3

    flag1, flag2, flag3 = asyncio.run(main())
    assert flag1 == "flag{test_presolve_dedup}"
    assert flag2 is None          # 去重：不再嗅探
    assert flag3 == "flag{test_presolve_dedup}"
    # 去重契约：flag_scan 实际嗅探 首次 1 次 + force 1 次 = 2（2nd 非 force 调用不重新嗅探）
    assert registry.calls["flag_scan"] == 2
    # 并发预扫契约：单次 presolve 6 路同时启动，故 crypto_auto 在「首轮 + force」各跑一次 = 2；
    # 2nd 非 force 调用被 mark_attempted 短路、不进嗅探循环，故不会到 3。intra-call 短路已让位
    # 于并发最低时延（2026-08-22 锐评整改的有意取舍）。
    assert registry.calls["crypto_auto"] == 2


def test_presolve_answer_mismatch_discarded():
    """本地答案校验：answers 提供且不匹配时命中被丢弃（返回 None）。"""
    from core.presolve import presolve

    registry = FakeRegistry()
    q = _question(attachments=["a.txt"], category="crypto")
    answers = {"q1": "flag{expected_real}"}  # 与假注册表返回的 flag 不同

    async def main():
        return await presolve(q, registry=registry, answers=answers)

    flag = asyncio.run(main())
    assert flag is None  # 命中但不匹配本地答案 → 丢弃改用 LLM


def test_presolve_no_attachments_does_not_mark():
    """无附件且无关键词 → 不标记（后续附件出现仍可重扫）。"""
    from core.presolve import presolve

    registry = FakeRegistry()
    q = _question(attachments=[], category="crypto", description="")

    async def main():
        flag1 = await presolve(q, registry=registry, answers=None)
        # 附件"出现"后再扫
        q.attachments = ["a.txt"]
        flag2 = await presolve(q, registry=registry, answers=None)
        return flag1, flag2

    flag1, flag2 = asyncio.run(main())
    assert flag1 is None
    assert flag2 == "flag{test_presolve_dedup}"  # 未被永久标记，可重扫


# ── poller 失败题重试队列 ────────────────────────────────────


class FakePlatform:
    """极简平台替身：list 返回 1 道题；get_challenge 可配置抛异常。"""

    def __init__(self, detail_fails=False):
        self.detail_fails = detail_fails

    async def list_challenges(self):
        from ctfplatform.base import ChallengeInfo
        return [ChallengeInfo(id="1001", title="t1", category="crypto")]

    async def get_challenge(self, challenge_id):
        if self.detail_fails:
            raise RuntimeError("HTTP 429")
        from ctfplatform.base import ChallengeInfo
        return ChallengeInfo(id=str(challenge_id), title="t1", category="crypto",
                             description="desc", has_attachment=False, has_instance=False)

    async def create_instance(self, challenge_id):
        from ctfplatform.base import InstanceInfo
        return InstanceInfo(instance_id="")

    async def destroy_instance(self, challenge_id):
        return None

    async def get_access(self, instance_id, challenge_id=""):
        from ctfplatform.base import AccessInfo
        return AccessInfo()

    async def submit_flag(self, challenge_id, flag):
        from ctfplatform.base import SubmitResult
        return SubmitResult(accepted=True)


def test_poller_detail_fail_goes_to_retry_queue():
    """详情拉取失败（429）→ 不入 processed，进重试队列可重试。"""
    from ctfplatform.poller import PlatformPoller

    platform = FakePlatform(detail_fails=True)

    async def solver(ch):
        return {"flag": ""}

    poller = PlatformPoller(platform=platform, solver=solver,
                            use_shared_progress=False, submit_after_solve=False)
    records = asyncio.run(poller.run_once())
    assert len(records) == 1
    assert records[0].error == "detail_fetch_failed"
    # 关键：失败的题不永久丢——不在 processed，在重试队列
    assert "1001" not in poller._processed
    assert "1001" in poller._retry_queue
    assert poller._retry_queue["1001"]["attempts"] == 1


def test_poller_retry_eventually_solves():
    """重试队列到点后重新处理：详情恢复 → 解出 → 入 processed。"""
    from ctfplatform.poller import PlatformPoller

    calls = {"detail": 0}

    class FlakyPlatform(FakePlatform):
        def __init__(self):
            super().__init__(detail_fails=True)

        async def get_challenge(self, challenge_id):
            calls["detail"] += 1
            if calls["detail"] == 1:
                raise RuntimeError("HTTP 429")  # 第一次失败
            from ctfplatform.base import ChallengeInfo
            return ChallengeInfo(id=str(challenge_id), title="t1", category="crypto",
                                 description="desc", has_attachment=False, has_instance=False)

    platform = FlakyPlatform()

    async def solver(ch):
        return {"flag": "flag{retry_ok}"}

    poller = PlatformPoller(platform=platform, solver=solver,
                            use_shared_progress=False, submit_after_solve=False)
    asyncio.run(poller.run_once())          # 第一次：失败进重试队列
    assert "1001" in poller._retry_queue
    # 手动把重试时间拨到过去（模拟 2-5 分钟过去）
    poller._retry_queue["1001"]["next_retry_at"] = 0.0
    records = asyncio.run(poller.run_once())  # 第二次：成功
    assert any(r.flag for r in records)
    assert "1001" in poller._processed
    assert "1001" not in poller._retry_queue
