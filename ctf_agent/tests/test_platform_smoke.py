# -*- coding: utf-8 -*-
"""平台层最小回归测试（P1 补强，2026-08-21）。

背景：此前 ctfplatform/ 平台层零测试，数据可达率靠产品/平台适配的 P0 修复撑着。
本文件锁定 dasctf.py 的核心契约（全部用可编程 FakeAsyncClient 替身 mock httpx，
不引第三方 mock 库，不真正联网）：

1. exercise-list 解析：corpus 展平 / 扁平结构 / 空数据 / 字段提取
   （id/category/score/attachment 多命名兼容）
2. HTTP 429 重试退避：连续 429 → 重试次数 + 退避间隔断言；Retry-After 尊重；
   重试耗尽返回 None（fail-open，不抛异常）
3. 附件下载失败 fallback：detail 请求失败 → 返回 []；相对 URL → 绝对 URL 转换
4. 字段缺失健壮性：get_challenge 收到残缺/空响应不抛异常，返回可处理结构
5. submit_flag：外壳剥离（官方手册第7条）+ 请求层失败 request_failed 传播

设计：全部同步测试函数 + asyncio.run，不依赖 pytest-asyncio。
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfplatform import dasctf  # noqa: E402


# ── 可编程 httpx 替身 ──────────────────────────────────────


class FakeResponse:
    """模拟 httpx.Response（仅暴露被测代码用到的字段）。"""

    def __init__(self, status_code=200, json_data=None, text="", content=None, headers=None):
        self.status_code = status_code
        self._json = json_data
        self.text = text
        # _request 用 resp.content 判空再 json()：200/201 默认给非空 content
        self.content = content if content is not None else (
            b"{}" if status_code in (200, 201) else b""
        )
        self.headers = headers or {}

    def json(self):
        return self._json


class FakeAsyncClient:
    """httpx.AsyncClient 替身：记录请求，按队列依次返回响应。"""

    def __init__(self, responses=None, *args, **kwargs):
        self._responses = list(responses or [])
        self.requests = []  # (method, url, headers, json, params)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _next(self):
        return self._responses.pop(0) if self._responses else FakeResponse()

    async def request(self, method, url, headers=None, json=None, params=None):
        self.requests.append((method, url, dict(headers or {}), json, params))
        return self._next()

    async def get(self, url, headers=None, **kwargs):
        # P1-12 兼容：dasctf 复用客户端后带 follow_redirects 等 kwargs，替身忽略
        self.requests.append(("GET", url, dict(headers or {}), None, None))
        return self._next()


def _patch_httpx(monkeypatch, fake_client) -> None:
    """把 httpx.AsyncClient 换成 fake_client（dasctf 内 import httpx 后取模块属性）。"""
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: fake_client)


def _make_platform(**kw) -> dasctf.DasCTFPlatform:
    kw.setdefault("base_url", "https://plat.example.com")
    kw.setdefault("token", "tok")
    return dasctf.DasCTFPlatform(**kw)


def _run(coro):
    return asyncio.run(coro)


# ── 1. exercise-list 解析 ──────────────────────────────────


def test_list_challenges_parses_corpus(monkeypatch):
    """官方结构 data=[{corpus:[...]}]：corpus 展平 + 字段提取。"""
    fake = FakeAsyncClient([FakeResponse(json_data={
        "data": [{
            "id": 10, "name": "CRYPTO-01",
            "corpus": [{
                "id": "1001", "name": "ezRSA", "category": "crypto",
                "score": "50.0", "attachment": {"url": "/files/a.zip"},
            }],
        }],
    })])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform()
    items = _run(pl.list_challenges())
    assert len(items) == 1
    ch = items[0]
    assert ch.id == "1001"
    assert ch.title == "ezRSA"
    assert ch.category == "crypto"
    assert ch.score == 50
    assert ch.has_attachment is True


def test_list_challenges_flat_without_corpus(monkeypatch):
    """兼容扁平结构（无 corpus 字段）。"""
    fake = FakeAsyncClient([FakeResponse(json_data={
        "data": [{"id": "2001", "name": "WEB-01", "category": "web"}],
    })])
    _patch_httpx(monkeypatch, fake)
    items = _run(_make_platform().list_challenges())
    assert len(items) == 1
    assert items[0].id == "2001"
    assert items[0].category == "web"


def test_list_challenges_empty_data(monkeypatch):
    """空 data → 空列表，不抛异常。"""
    fake = FakeAsyncClient([FakeResponse(json_data={"data": []})])
    _patch_httpx(monkeypatch, fake)
    assert _run(_make_platform().list_challenges()) == []


def test_list_challenges_none_response(monkeypatch):
    """请求失败（500）→ fail-open 返回 []。"""
    fake = FakeAsyncClient([FakeResponse(status_code=500, text="boom")])
    _patch_httpx(monkeypatch, fake)
    assert _run(_make_platform().list_challenges()) == []


# ── 2. 429 重试退避 ───────────────────────────────────────


def test_retry_429_backoff(monkeypatch):
    """连续 429 → 重试 3 次，退避间隔 = retry_backoff * 2**attempt。"""
    waits = []

    async def _fake_sleep(sec):
        waits.append(sec)

    monkeypatch.setattr(dasctf, "asyncio_sleep", _fake_sleep)
    fake = FakeAsyncClient([
        FakeResponse(status_code=429, text="rate"),
        FakeResponse(status_code=429, text="rate"),
        FakeResponse(status_code=200, json_data={"ok": 1}),
    ])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform(max_retries=5, retry_backoff=2.0)
    result = _run(pl._request("GET", "challenges"))
    assert result == {"ok": 1}
    assert len(fake.requests) == 3
    assert waits == [2.0, 4.0]  # attempt0→2.0, attempt1→4.0


def test_retry_429_respects_retry_after(monkeypatch):
    """带 Retry-After 头时按其值等待（优先于退避公式）。"""
    waits = []

    async def _fake_sleep(sec):
        waits.append(sec)

    monkeypatch.setattr(dasctf, "asyncio_sleep", _fake_sleep)
    fake = FakeAsyncClient([
        FakeResponse(status_code=429, text="rate", headers={"Retry-After": "1"}),
        FakeResponse(status_code=200, json_data={"ok": 1}),
    ])
    _patch_httpx(monkeypatch, fake)
    result = _run(_make_platform(max_retries=5, retry_backoff=2.0)._request("GET", "challenges"))
    assert result == {"ok": 1}
    assert waits == [1.0]


def test_retry_exhausted_returns_none(monkeypatch):
    """429 重试耗尽 → 返回 None（fail-open，不抛异常）。"""
    waits = []

    async def _fake_sleep(sec):
        waits.append(sec)

    monkeypatch.setattr(dasctf, "asyncio_sleep", _fake_sleep)
    fake = FakeAsyncClient([FakeResponse(status_code=429, text="rate")] * 5)
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform(max_retries=5, retry_backoff=0.1)
    result = _run(pl._request("GET", "challenges"))
    assert result is None
    assert len(fake.requests) == 5


# ── 3. 附件下载 fallback ──────────────────────────────────


def test_download_attachment_failure_fallback(monkeypatch):
    """detail 请求失败 → 返回 []，不抛异常（数据可达性兜底）。"""
    fake = FakeAsyncClient([FakeResponse(status_code=500, text="boom")])
    _patch_httpx(monkeypatch, fake)
    assert _run(_make_platform().download_attachment("1001")) == []


def test_download_attachment_relative_to_absolute(monkeypatch):
    """相对 URL → 拼接 base_url 成绝对 URL。"""
    fake = FakeAsyncClient([FakeResponse(json_data={
        "data": {"attachment": {"url": "/slab-match/files/a.zip"}},
    })])
    _patch_httpx(monkeypatch, fake)
    urls = _run(_make_platform().download_attachment("1001"))
    assert urls == ["https://plat.example.com/slab-match/files/a.zip"]


def test_download_attachment_bytes_non200_raises(monkeypatch):
    """附件字节下载非 200 → 抛 RuntimeError（让上层 fallback 到源码分析）。"""
    fake = FakeAsyncClient([FakeResponse(status_code=403, text="denied")])
    _patch_httpx(monkeypatch, fake)
    with pytest.raises(RuntimeError):
        _run(_make_platform().download_attachment_bytes("https://x/a.zip"))


# ── 4. 字段缺失健壮性 ─────────────────────────────────────


def test_get_challenge_missing_fields_no_raise(monkeypatch):
    """详情只有 id → 不抛异常，category 回落默认 misc，title 回落 id。"""
    fake = FakeAsyncClient([FakeResponse(json_data={"data": {"id": "1001"}})])
    _patch_httpx(monkeypatch, fake)
    ch = _run(_make_platform().get_challenge("1001"))
    assert isinstance(ch, dasctf.ChallengeInfo)
    assert ch.id == "1001"
    assert ch.category == "misc"
    assert ch.title == "1001"


def test_get_challenge_empty_response_no_raise(monkeypatch):
    """详情请求失败/空 → 返回 id 占位 ChallengeInfo，不抛异常。"""
    fake = FakeAsyncClient([FakeResponse(status_code=500, text="boom")])
    _patch_httpx(monkeypatch, fake)
    ch = _run(_make_platform().get_challenge("9999"))
    assert isinstance(ch, dasctf.ChallengeInfo)
    assert ch.id == "9999"


# ── 5. submit_flag ────────────────────────────────────────


def test_submit_flag_strips_wrapper():
    """官方手册第7条：提交时剥离 flag{}/DASCTF{} 外壳。"""
    assert dasctf._strip_flag_wrapper("flag{rsa_small_e_2026}") == "rsa_small_e_2026"
    assert dasctf._strip_flag_wrapper("DASCTF{abc-123}") == "abc-123"
    assert dasctf._strip_flag_wrapper("raw_value_no_braces") == "raw_value_no_braces"


def test_submit_flag_request_failed_propagates(monkeypatch):
    """请求层失败 → request_failed=True（正确 flag 不被静默丢弃）。"""
    fake = FakeAsyncClient([FakeResponse(status_code=500, text="gateway")])
    _patch_httpx(monkeypatch, fake)
    res = _run(_make_platform().submit_flag("1001", "flag{abc}"))
    assert res.accepted is False
    assert res.request_failed is True


# ── 6. P0 数据链路修复回归（产品官 2026-08-21 改动）───────────


def test_list_challenges_ttl_cache(monkeypatch):
    """TTL 内重复调用命中缓存，不发起网络请求（429 风暴根因修复）。"""
    fake = FakeAsyncClient([
        FakeResponse(json_data={"data": [{"id": "1", "name": "A"}]}),
        FakeResponse(json_data={"data": [{"id": "2", "name": "B"}]}),
    ])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform()
    pl._list_cache_ttl = 3600.0  # TTL 内必然命中
    first = _run(pl.list_challenges())
    second = _run(pl.list_challenges())
    assert len(fake.requests) == 1          # 第二次不发请求
    assert [c.id for c in first] == [c.id for c in second] == ["1"]


def test_list_challenges_ttl_expiry(monkeypatch):
    """TTL 过期后重新发起请求。"""
    fake = FakeAsyncClient([
        FakeResponse(json_data={"data": [{"id": "1"}]}),
        FakeResponse(json_data={"data": [{"id": "2"}]}),
    ])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform()
    pl._list_cache_ttl = 0.0  # 立即过期
    _run(pl.list_challenges())
    _run(pl.list_challenges())
    assert len(fake.requests) == 2


def test_last_list_ok_true_on_empty_success(monkeypatch):
    """HTTP 200 空列表 = 真实成功，不是故障（last_list_ok=True）。"""
    fake = FakeAsyncClient([FakeResponse(json_data={"data": []})])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform()
    assert _run(pl.list_challenges()) == []
    assert pl.last_list_ok() is True


def test_last_list_ok_false_on_failure(monkeypatch):
    """请求失败 → last_list_ok=False（轮询层据此退避）。"""
    waits = []

    async def _fake_sleep(sec):
        waits.append(sec)

    monkeypatch.setattr(dasctf, "asyncio_sleep", _fake_sleep)
    fake = FakeAsyncClient([FakeResponse(status_code=500, text="x")] * 5)
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform(max_retries=5)
    assert _run(pl.list_challenges()) == []
    assert pl.last_list_ok() is False


def test_backoff_suggestion_ladder():
    """连续 429 阶梯：≥3→30s ≥5→60s ≥8→120s ≥12→300s；无 429→0。"""
    pl = _make_platform()
    assert pl.backoff_suggestion(30) == 0.0
    pl._consec_429 = 3
    assert pl.backoff_suggestion(30) == 30.0
    pl._consec_429 = 5
    assert pl.backoff_suggestion(30) == 60.0
    pl._consec_429 = 8
    assert pl.backoff_suggestion(30) == 120.0
    pl._consec_429 = 12
    assert pl.backoff_suggestion(30) == 300.0


def test_backoff_suggestion_zero_when_no_429():
    """无 429 时不干预（返回 0），避免误伤放题高频窗口。"""
    pl = _make_platform()
    assert pl._consec_429 == 0
    assert pl.backoff_suggestion(5.0) == 0.0


def test_consec_429_accumulates_and_resets(monkeypatch):
    """连续 429 累加计数；请求成功即重置（阶梯在成功后回落）。"""
    waits = []

    async def _fake_sleep(sec):
        waits.append(sec)

    monkeypatch.setattr(dasctf, "asyncio_sleep", _fake_sleep)
    fake = FakeAsyncClient([
        FakeResponse(status_code=429, text="rate"),
        FakeResponse(status_code=429, text="rate"),
        FakeResponse(status_code=429, text="rate"),
        FakeResponse(status_code=200, json_data={"ok": 1}),
    ])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform(max_retries=5, retry_backoff=0.1)
    assert _run(pl._request("GET", "challenges")) == {"ok": 1}
    assert pl._consec_429 == 0  # 成功重置


def test_download_attachment_reuses_detail_cache(monkeypatch):
    """get_challenge 已填充 5min 缓存 → download_attachment 不再二次发请求。"""
    fake = FakeAsyncClient([FakeResponse(json_data={
        "data": {"id": "1001", "attachment": {"url": "/slab-match/files/a.zip"}},
    })])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform()
    _run(pl.get_challenge("1001"))
    urls = _run(pl.download_attachment("1001"))
    assert urls == ["https://plat.example.com/slab-match/files/a.zip"]
    assert len(fake.requests) == 1  # 全程仅 1 次请求


def test_download_attachment_url_from_description(monkeypatch):
    """attachment 为空但 description 含 https URL → 提取为附件 URL（大文件题）。"""
    detail = {"id": "2001", "attachment": {},
              "description": "附件: https://20260818-atta.dasctf.com/06_mysql_xxx.zip"}
    fake = FakeAsyncClient([FakeResponse(json_data={"data": detail}),
                            FakeResponse(json_data={"data": detail})])
    _patch_httpx(monkeypatch, fake)
    pl = _make_platform()
    urls = _run(pl.download_attachment("2001"))
    assert any("06_mysql_xxx.zip" in u for u in urls)


def test_extract_attachment_urls_variants():
    """附件字段多形态提取（url/downloadUrl/src/path/files/list/str）。"""
    assert dasctf._extract_attachment_urls({"url": "/a.zip"}) == ["/a.zip"]
    assert dasctf._extract_attachment_urls({"downloadUrl": "https://x/b.zip"}) == ["https://x/b.zip"]
    assert dasctf._extract_attachment_urls({"src": "/c.zip"}) == ["/c.zip"]
    assert dasctf._extract_attachment_urls({"files": [{"url": "/d.zip"}, {"name": "e.zip"}]}) == ["/d.zip"]
    assert dasctf._extract_attachment_urls(["/f.zip", "https://g.zip"]) == ["/f.zip", "https://g.zip"]
    assert dasctf._extract_attachment_urls("https://h.zip") == ["https://h.zip"]
    assert dasctf._extract_attachment_urls(None) == []


def test_parse_challenge_description_fallback():
    """描述性标题兜底为 description；裸"题型-编号"不兜底（防 no-data 止损失效）。"""
    ch = dasctf._parse_challenge({"id": "3001", "title": "rabbit encryption"})
    assert ch.description == "rabbit encryption"
    ch2 = dasctf._parse_challenge({"id": "3002", "title": "CRYPTO-32"})
    assert ch2.description == ""
