# -*- coding: utf-8 -*-
"""P0 附件/靶机注入 harness 单测（离线、零网络、零平台凭证）。

覆盖：
- 完整题（有附件 + 有靶机）：附件下载落地、靶机注入、inventory 标记、注入 prompt 非空；
- 无数据题：has_attachment/has_target 均 False → should_early_exit 触发（backlog P0 早退）；
- 详情拉取失败（429 模拟）：detail_fetch_failed 标记正确、且不误伤已有真实数据；
- 附件下载失败（字节为空）：降级为空附件列表、不抛异常、仍可判定早退。
- reverse 题（二进制附件 + 靶机）：二进制落地、靶机注入、不早退 —— 证明 P0 harness 覆盖 P3 reverse live 路径；
- misc 题（仅靶机、无附件）：靶机视为可解输入、不早退 —— 证明纯靶机类 misc 也能进入求解。
"""

import asyncio
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfplatform.base import ChallengeInfo, AccessInfo  # noqa: E402

from core.attachment_harness import (  # noqa: E402
    InputInventory,
    build_injection_prompt,
    prepare_question,
)


class FakePlatform:
    """测试用平台：完全内存态，不触网。"""

    def __init__(self, detail=None, attachment_urls=None, attachment_bytes=b"fakedata",
                 access=None, empty_detail=False, raise_detail=False):
        # detail：get_challenge 返回的 ChallengeInfo（含 extra）
        self._detail = detail
        self._urls = attachment_urls or []
        self._bytes = attachment_bytes
        self._access = access
        # empty_detail：模拟 429 返回空 ChallengeInfo（无异常，run.py 视为"无数据"不标失败）
        self._empty_detail = empty_detail
        # raise_detail：模拟网络/鉴权异常（run.py 走 except 分支标 detail_fetch_failed）
        self._raise_detail = raise_detail
        self.get_challenge_calls = 0

    async def get_challenge(self, challenge_id):
        self.get_challenge_calls += 1
        if self._raise_detail:
            raise RuntimeError("HTTP 429 / network error")
        if self._empty_detail:
            return ChallengeInfo(id=challenge_id)
        return self._detail

    async def download_attachment(self, challenge_id):
        return list(self._urls)

    async def download_attachment_bytes(self, url):
        if self._bytes is None:
            raise RuntimeError("download failed")
        return self._bytes

    async def get_access(self, instance_id="", challenge_id=""):
        return self._access


def _ch(**kw) -> ChallengeInfo:
    return ChallengeInfo(**kw)


@pytest.mark.asyncio
async def test_full_challenge_injects_attachment_and_target(tmp_path):
    detail = ChallengeInfo(
        id="c1", title="CRYPTO-01", category="crypto",
        description="RSA small e", flag_format=r"flag\{[^}]+\}",
        has_attachment=True, extra={"difficulty": "medium", "attachment": {"url": "http://x/a.zip"}},
    )
    access = AccessInfo(host="10.0.0.5", port=8080, url="http://10.0.0.5:8080")
    platform = FakePlatform(
        detail=detail,
        attachment_urls=["http://example.com/secret.zip"],
        access=access,
    )
    ch = _ch(id="c1", title="CRYPTO-01", category="crypto", description="",
             has_attachment=True, extra={})

    question, inv = await prepare_question(platform, ch, cache_dir=str(tmp_path))

    # 附件下载落地
    assert inv.has_attachment is True
    assert len(inv.attachment_paths) == 1
    assert os.path.exists(inv.attachment_paths[0])
    assert question.attachments == inv.attachment_paths

    # 靶机注入（来自显式 get_access，不依赖 poller 预填）
    assert inv.has_target is True
    assert any("10.0.0.5" in t for t in inv.targets)
    assert "targets" in question.extra
    assert "靶机" in question.description

    # 早退判定：有输入 → 不应早退
    early, reason = inv.should_early_exit()
    assert early is False and reason == ""
    assert inv.has_solvable_input() is True

    # 注入 prompt 非空且含附件路径与靶机
    prompt = build_injection_prompt(inv, question)
    assert prompt and inv.attachment_paths[0] in prompt and "10.0.0.5" in prompt


@pytest.mark.asyncio
async def test_no_data_triggers_early_exit(tmp_path):
    # 列表阶段题：无 description、has_attachment=False、无 endpoints
    detail = ChallengeInfo(id="c2", title="MISC-01", category="misc",
                           description="", extra={})
    platform = FakePlatform(detail=detail, attachment_urls=[], access=AccessInfo())
    ch = _ch(id="c2", title="MISC-01", category="misc", description="",
             has_attachment=False, extra={})

    question, inv = await prepare_question(platform, ch, cache_dir=str(tmp_path))

    assert inv.has_attachment is False
    assert inv.has_target is False
    assert inv.has_solvable_input() is False

    early, reason = inv.should_early_exit()
    assert early is True and reason == "no_attachment_no_target"
    # 早退时注入 prompt 应为空（交由调用方跳过求解）
    assert build_injection_prompt(inv, question) == ""


@pytest.mark.asyncio
async def test_detail_fetch_failed_marks_and_keeps_existing_data(tmp_path):
    # 情形 A：429 返回空 ChallengeInfo（无异常）—— 对齐 run.py：不标 detail_fetch_failed，
    # 但 inventory 无任何输入 → 仍应早退（由 has_solvable_input 判定）
    platform = FakePlatform(empty_detail=True)
    ch = _ch(id="c3", title="WEB-01", category="web", description="",
             has_attachment=False, extra={})
    _, inv = await prepare_question(platform, ch, cache_dir=str(tmp_path),
                                    retry_sleep=0)
    assert inv.detail_fetch_failed is False  # 忠实复刻 run.py：空 extra 不标失败
    assert platform.get_challenge_calls == 2  # 确实重试了一次
    assert inv.should_early_exit() == (True, "no_attachment_no_target")

    # 情形 B：get_challenge 抛异常（网络/鉴权）—— 走 except 分支标 detail_fetch_failed=True
    platform_ex = FakePlatform(raise_detail=True)
    ch_ex = _ch(id="c3b", title="WEB-01b", category="web", description="",
               has_attachment=False, extra={})
    _, inv_ex = await prepare_question(platform_ex, ch_ex, cache_dir=str(tmp_path),
                                       retry_sleep=0)
    assert inv_ex.detail_fetch_failed is True

    # 情形 C：ch 已有真实 endpoints，但 get_challenge 抛异常 → 不应误标失败、靶机仍生效
    platform2 = FakePlatform(raise_detail=True)
    ch2 = _ch(id="c4", title="WEB-02", category="web", description="real desc",
              has_attachment=False,
              extra={"endpoints": [{"exposeIps": ["9.9.9.9:9999"]}]})
    _, inv2 = await prepare_question(platform2, ch2, cache_dir=str(tmp_path),
                                    retry_sleep=0)
    assert inv2.detail_fetch_failed is False
    assert inv2.has_target is True  # endpoints 提取的靶机仍生效


@pytest.mark.asyncio
async def test_attachment_download_failure_degrades_gracefully(tmp_path):
    detail = ChallengeInfo(id="c5", title="CRYPTO-02", category="crypto",
                          description="x", has_attachment=True,
                          extra={"attachment": {"url": "http://x/b.zip"}})
    # 下载字节返回 None → 模拟下载失败
    platform = FakePlatform(detail=detail, attachment_urls=["http://x/b.zip"],
                           attachment_bytes=None, access=AccessInfo())
    ch = _ch(id="c5", title="CRYPTO-02", category="crypto", description="",
             has_attachment=True, extra={})

    question, inv = await prepare_question(platform, ch, cache_dir=str(tmp_path))

    # 下载失败 → 无附件路径，但不抛异常；无靶机 → 应早退
    assert inv.attachment_paths == []
    assert inv.has_attachment is False
    early, reason = inv.should_early_exit()
    assert early is True
    assert question.attachments == []


@pytest.mark.asyncio
async def test_reverse_challenge_injects_binary_and_target(tmp_path):
    # P3 关键用例：真实 DASCTF reverse 题需要 (1) 二进制附件落地给 file_analyze；(2) 靶机注入。
    # 旧 build_platform_solver 闭包依赖 ch.extra["access"]（poller 从未预填）→ 靶机永不注入，
    # 这正是 reverse/misc 0 解的根因之一。harness 显式调 get_access + _extract_targets 兜底。
    detail = ChallengeInfo(
        id="r1", title="RE-01", category="reverse",
        description="crackme", flag_format=r"flag\{[^}]+\}",
        has_attachment=True,
        extra={"difficulty": "hard",
               "attachment": {"url": "http://x/re1.bin"},
               "endpoints": [{"exposeIps": ["10.1.2.3:9999"]}]},
    )
    access = AccessInfo(host="10.1.2.3", port=9999, url="http://10.1.2.3:9999")
    platform = FakePlatform(
        detail=detail,
        attachment_urls=["http://example.com/re1.bin"],
        access=access,
    )
    ch = _ch(id="r1", title="RE-01", category="reverse", description="",
             has_attachment=True, extra={})

    question, inv = await prepare_question(platform, ch, cache_dir=str(tmp_path))

    # 二进制附件下载落地（file_analyze 可拿到的输入）
    assert inv.has_attachment is True
    assert len(inv.attachment_paths) == 1
    assert os.path.exists(inv.attachment_paths[0])
    assert question.attachments == inv.attachment_paths

    # 靶机注入（来自显式 get_access + endpoints 兜底）
    assert inv.has_target is True
    assert any("10.1.2.3" in t for t in inv.targets)
    assert "靶机" in question.description

    # 有输入 → 不应早退（reverse 题应能进入求解）
    early, reason = inv.should_early_exit()
    assert early is False and reason == ""
    assert inv.has_solvable_input() is True
    prompt = build_injection_prompt(inv, question)
    assert prompt and inv.attachment_paths[0] in prompt and "10.1.2.3" in prompt


@pytest.mark.asyncio
async def test_misc_challenge_target_only_no_early_exit(tmp_path):
    # 纯靶机类 misc（如流量分析 remote 靶机）：无附件但有靶机 → 靶机视为可解输入，不早退。
    detail = ChallengeInfo(
        id="m1", title="MISC-01", category="misc", description="",
        has_attachment=False,
        extra={"endpoints": [{"exposeIps": ["10.9.9.9:5000"]}]},
    )
    access = AccessInfo(host="10.9.9.9", port=5000, url="http://10.9.9.9:5000")
    platform = FakePlatform(detail=detail, attachment_urls=[], access=access)
    ch = _ch(id="m1", title="MISC-01", category="misc", description="",
             has_attachment=False, extra={})

    question, inv = await prepare_question(platform, ch, cache_dir=str(tmp_path))

    assert inv.has_attachment is False
    assert inv.has_target is True
    early, reason = inv.should_early_exit()
    assert early is False and reason == ""  # 靶机是可解输入，不早退
    assert inv.has_solvable_input() is True


def test_input_inventory_defaults():
    inv = InputInventory(challenge_id="x")
    assert inv.should_early_exit() == (True, "no_attachment_no_target")
    assert inv.has_solvable_input() is False
