"""DasCTFPlatform：西湖论剑官方平台完整 API 客户端。

阶段 5 实现：在抽象层预留的完整生命周期上填充通用 HTTP 客户端逻辑。
- Token 鉴权：Agent-Token 请求头（可配置）
- 通用请求：openapi 自动发现 + 重试 + fail-open 异常处理
- 端点路径可配置（endpoints 字典），不强耦合假设性固定字段——
  测试赛拿到官方 openapi.json 后，仅需调整 endpoints 映射即可适配。
- 所有方法返回类型安全（失败返回空值/默认对象，不抛异常）

⚠️ 参考：端点命名对齐通用 AI-Agent CTF 平台模式（agent-operator.md），
正式路径以测试赛官方 openapi.json 为准（通过 endpoints 参数覆盖）。
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

from ctfplatform.base import (
    AccessInfo,
    ChallengeInfo,
    InstanceInfo,
    PlatformAPI,
    SubmitResult,
)

# 默认端点映射（对齐官方 AI Agent API 文档，2026-08-18 确认）
DEFAULT_ENDPOINTS = {
    "openapi": "/openapi.json",
    # ── 官方 AI Agent API（api_doc.md）──
    "match_info": "/slab-match/api/v1/agent/match/notice/match-info",      # GET 竞赛规则
    "overview": "/slab-match/api/v1/agent/answer-panel/overview",          # GET 得分排名
    "challenges": "/slab-match/api/v1/agent/ctf/exercise-list",            # GET 题目列表
    "challenge_detail": "/slab-match/api/v1/agent/ctf/exercise",           # GET 题目详情 ?exerciseId=
    "build_env": "/slab-match/api/v1/agent/ctf/build-exercise-env",        # POST 启动环境
    "recover_env": "/slab-match/api/v1/agent/ctf/recover-exercise-env",    # POST 回收环境
    "submit": "/slab-match/api/v1/agent/answer-panel/answer",              # POST 提交答案
    "notice_list": "/slab-match/api/v1/agent/match/notice/now-list",       # GET 公告列表
    "notice_detail": "/slab-match/api/v1/agent/match/notice/detail",       # GET 公告详情 ?id=
}


class DasCTFPlatform(PlatformAPI):
    """西湖论剑答题平台实现（完整 HTTP 客户端）。

    测试赛便捷配置：base_url/token 支持从环境变量读取（DASCTF_BASE_URL、
    DASCTF_TOKEN / CTF_AGENT_PLATFORM_TOKEN），无需改代码即可对接官方平台。
    """

    def __init__(
        self,
        base_url: str = "",
        token: str = "",
        endpoints: Optional[dict] = None,
        timeout: float = 30.0,
        max_retries: int = 5,
        retry_backoff: float = 2.0,
        auth_header: str = "X-Agent-AccessKey",  # 官方 API 文档：Agent 专用 AccessKey
    ) -> None:
        import os

        # 环境变量优先（测试赛无需改代码）：DASCTF_BASE_URL / DASCTF_TOKEN
        # 注册表回退：setx 写入后当前进程环境变量不刷新（新进程才生效），
        # 从 HKCU\Environment 读最新值（Windows 下 setx 的落地位置）
        def _env_or_registry(name: str) -> str:
            val = os.getenv(name, "").strip()
            if val:
                return val
            try:
                import winreg

                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                    value, _ = winreg.QueryValueEx(k, name)
                    return str(value).strip()
            except OSError:
                return ""

        base_url = base_url or _env_or_registry("DASCTF_BASE_URL")
        token = token or _env_or_registry("DASCTF_TOKEN") \
            or _env_or_registry("CTF_AGENT_PLATFORM_TOKEN")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.endpoints = {**DEFAULT_ENDPOINTS, **(endpoints or {})}
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.auth_header = auth_header
        self._openapi: Optional[dict] = None
        # ── 429 限流状态 + 列表 TTL 缓存（P0 数据链路修复 2026-08-21）──
        # _consec_429：连续 429 计数，成功即重置，驱动轮询退避阶梯
        self._consec_429: int = 0
        # ── 403 WAF 风控（P0 修复 2026-08-21 初赛：3s 高频轮询触发平台
        #    「疑似攻击行为」403 封禁，直接丧失拉题能力）──
        # _waf_blocked_until：monotonic 时间戳，该时刻前所有平台请求直接冻结跳过。
        # 一旦命中 403 → 冷却 300s（5 分钟），期间 poller 不打扰平台。
        self._waf_blocked_until: float = 0.0
        self.WAF_COOLDOWN_SECONDS: float = 300.0
        # _last_list_ok：最近一次 list_challenges 是否真实成功（HTTP 200）。
        # 区分「拉取到 0 道题（200 但空）」与「请求失败（429/5xx）」，避免把
        # 合法空结果误判为故障而退避。
        self._last_list_ok: bool = True
        # 列表 TTL 缓存：默认 10s 内复用上次拉取结果，杜绝"拉取到 0 道题"时
        # 每 3-5s 一次重复请求（赛时 429 风暴根因之一）
        self._list_cache: Optional[tuple] = None  # (monotonic_ts, list[ChallengeInfo])
        self._list_cache_ttl: float = float(os.getenv("CTF_AGENT_LIST_TTL", "10"))
        # P1-12 修复（2026-08-21 赛后）：AsyncClient 连接复用——按事件循环缓存
        # 一个 httpx.AsyncClient（原每次请求新建，429 风暴下连接建立开销放大）。
        # 按 loop id 缓存避免跨事件循环复用（asyncio.run 多次调用场景安全）。
        self._clients: dict = {}
        logger.info("DasCTFPlatform 初始化（base_url=%s, 端点=%d 个）",
                    base_url or "(未配置)", len(self.endpoints))

    # ── AsyncClient 复用（P1-12）────────────────────────

    def _get_client(self):
        """返回当前事件循环的复用 AsyncClient（懒创建；按 loop id 隔离）。"""
        import asyncio
        import httpx

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        key = id(loop) if loop is not None else 0
        client = self._clients.get(key)
        if client is None:
            client = httpx.AsyncClient(timeout=self.timeout, trust_env=False)
            self._clients[key] = client
        return client

    def close(self) -> None:
        """关闭全部复用客户端（进程退出/测试收尾时调用；不抛异常）。"""
        for _k, _c in list(self._clients.items()):
            try:
                _c.aclose()
            except Exception:  # noqa: BLE001
                pass
        self._clients.clear()

    # ── 底层请求（重试 + fail-open）──────────────────────

    async def _request(
        self,
        method: str,
        endpoint_key: str,
        path_params: Optional[dict] = None,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[dict]:
        """发起请求：路径拼接 + Token 鉴权 + 指数退避重试 + fail-open。

        Returns:
            响应 JSON（dict）；任何失败返回 None（不抛异常）
        """
        template = self.endpoints.get(endpoint_key, "")
        path = template.format(**(path_params or {}))
        url = f"{self.base_url}{path}" if self.base_url else path
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
            self.auth_header: self.token,
        }

        last_error: Optional[Exception] = None
        self._last_error = ""   # 记录最近一次请求层失败（HTTP 状态码/异常），供 submit 暴露真实错误（第⑥层修复）
        for attempt in range(self.max_retries):
            try:
                # ── WAF 冷却冻结检查（403 命中后 5 分钟内不打扰平台）──
                if self._waf_blocked_until > 0:
                    import time as _t
                    remain = self._waf_blocked_until - _t.monotonic()
                    if remain > 0:
                        logger.warning("WAF 风控冷却中（剩余 %.0fs），跳过平台请求", remain)
                        self._last_error = f"WAF 风控冷却中({remain:.0f}s)"
                        return None
                    self._waf_blocked_until = 0.0
                # P1-12 修复（2026-08-21 赛后）：复用 AsyncClient（连接池），不再每次新建
                client = self._get_client()
                resp = await client.request(
                    method, url, headers=headers, json=json_body, params=params
                )
                if resp.status_code == 403:
                    # WAF 风控（初赛 0 解出根因：3s 高频轮询触发「疑似攻击行为」封禁）
                    import time as _t2
                    self._waf_blocked_until = _t2.monotonic() + self.WAF_COOLDOWN_SECONDS
                    logger.error(
                        "❌ 平台 403 WAF 风控！冻结请求 %.0fs（初赛高频轮询触发封禁的教训；"
                        "冷却期间 poller 自动退避，勿手动加速）",
                        self.WAF_COOLDOWN_SECONDS,
                    )
                    self._last_error = "HTTP 403 WAF 风控（冷却 300s）"
                    return None
                if resp.status_code in (200, 201):
                    # 请求成功 → 重置连续 429 计数（P0 修复：退避阶梯在成功后回退）
                    self._consec_429 = 0
                    if resp.content:
                        try:
                            return resp.json()
                        except json.JSONDecodeError:
                            return {"raw": resp.text}
                    return {}
                # 550 = 腾讯云网关对后端 500 的包装（赛中平台抖动常见），554 = 网关超时，纳入重试
                if resp.status_code in (429, 500, 502, 503, 504, 550, 554):
                    # 可重试状态码：指数退避 + 尊重 Retry-After 头
                    # 429 时累加连续计数（P0 修复：轮询层据此动态拉长间隔）
                    if resp.status_code == 429:
                        self._consec_429 += 1
                    last_error = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
                    self._last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            wait = float(retry_after)
                        except (ValueError, TypeError):
                            wait = self.retry_backoff * (2 ** attempt)
                    else:
                        wait = self.retry_backoff * (2 ** attempt)
                    # P0-4 修复（2026-08-21 赛后）：429 退避上限从 ~62s 降到 ~15s——
                    # 快速失败让 poller 层统一控制轮询节奏（30s→60s→120s→300s）。
                    wait = min(wait, 15.0)
                    await asyncio_sleep(wait)
                    continue
                logger.warning("平台请求失败 HTTP %s: %s", resp.status_code, resp.text[:200])
                self._last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                return None
            except Exception as exc:  # noqa: BLE001 - 网络异常 fail-open
                last_error = exc
                self._last_error = f"{type(exc).__name__}: {exc}"
                await asyncio_sleep(min(self.retry_backoff * (2 ** attempt), 15.0))

        logger.warning("平台请求重试耗尽: %s %s（%s）", method, url, last_error)
        self._last_error = f"重试耗尽({self.max_retries}次): {last_error}"
        return None

    async def discover_openapi(self) -> Optional[dict]:
        """拉取 openapi.json（自动发现接口；失败不阻塞）。"""
        if self._openapi is not None:
            return self._openapi
        if not self.base_url:
            return None
        try:
            # P1-12 修复（2026-08-21 赛后）：复用 AsyncClient（连接池）
            client = self._get_client()
            resp = await client.get(
                f"{self.base_url}{self.endpoints['openapi']}", follow_redirects=True)
            if resp.status_code == 200:
                self._openapi = resp.json()
                logger.info("openapi.json 已发现（%d 个路径）", len(self._openapi.get("paths", {})))
        except Exception as exc:  # noqa: BLE001
            logger.warning("openapi 发现失败（不影响后续请求）: %s", exc)
        return self._openapi

    # ── 限流感知（P0 数据链路修复 2026-08-21：轮询退避的数据源）────────

    def backoff_suggestion(self, base: float) -> float:
        """根据连续 429 次数给出建议轮询间隔（秒）；无 429 时返回 0（不干预）。

        阶梯：连续 429 ≥3 → 30s；≥5 → 60s；≥8 → 120s；≥12 → 300s（上限）。
        成功后 _request 会重置 _consec_429，间隔自然回落。调用方仅在返回值 >0
        时才覆盖当前间隔，避免误伤放题高频窗口。
        """
        n = self._consec_429
        if n >= 12:
            return 300.0
        if n >= 8:
            return 120.0
        if n >= 5:
            return 60.0
        if n >= 3:
            return 30.0
        return 0.0

    def waf_blocked(self) -> float:
        """WAF 风控冷却剩余秒数（>0 = 封禁中，poller 应拉长轮询间隔）。"""
        import time as _t
        if self._waf_blocked_until <= 0:
            return 0.0
        remain = self._waf_blocked_until - _t.monotonic()
        return max(remain, 0.0)

    def last_list_ok(self) -> bool:
        """最近一次 list_challenges 是否真实成功（HTTP 200，含空列表）。"""
        return self._last_list_ok

    # ── 全生命周期实现 ───────────────────────────────────

    async def list_challenges(self) -> list[ChallengeInfo]:
        import time as _t

        # P0 修复（2026-08-21）：列表 TTL 缓存——轮询循环每 3-5s 调一次
        # exercise-list，赛时 37 次/轮 429 风暴根因之一。TTL 内直接复用，
        # 拉取到 0 道题时也不重复请求。
        try:
            _lc = self._list_cache
            if _lc and (_t.monotonic() - _lc[0]) < self._list_cache_ttl:
                return _lc[1]
        except AttributeError:  # noqa: BLE001 - 旧实例无缓存字段时跳过
            pass
        data = await self._request("GET", "challenges")
        if not data:
            # 请求失败（429/5xx/网络）→ 标记非 OK，返回空；轮询层据此退避
            self._last_list_ok = False
            logger.warning("list_challenges 请求失败（429 连续 %d 次），返回空列表",
                           self._consec_429)
            return []
        self._last_list_ok = True
        # 官方结构：data = [{id,name,order,corpus:[{id,name,order,isOpen,hasSolved}]}]
        # 展平 corpus 得到题目列表
        raw = data.get("data") or data.get("challenges") or []
        items = []
        for entry in raw:
            if isinstance(entry, dict):
                if "corpus" in entry:
                    # 分类容器：只取 corpus 内题目（空 corpus = 该批次还没放题，跳过）
                    items.extend(entry.get("corpus") or [])
                else:
                    # 扁平题目（无 corpus 字段，兼容旧结构）
                    items.append(entry)
            else:
                items.append(entry)
        result = []
        for item in items:
            if isinstance(item, dict):
                result.append(_parse_challenge(item))
        try:
            self._list_cache = (_t.monotonic(), result)
        except Exception:  # noqa: BLE001 - 缓存失败不影响
            pass
        logger.info("拉取到 %d 道题", len(result))
        return result

    async def get_challenge(self, challenge_id: str) -> ChallengeInfo:
        # P0 修复（2026-08-21 正式赛）：详情缓存——poller 与 scan 每轮每题都调
        # get_challenge，平台 550 限流（31 次/轮）。加 5 分钟 TTL 内存缓存。
        import time as _t

        try:
            _c = self._detail_cache
        except AttributeError:
            _c = self._detail_cache = {}
        _now = _t.monotonic()
        _hit = _c.get(str(challenge_id))
        if _hit and _now - _hit[0] < 300:
            return _hit[1]
        data = await self._request(
            "GET", "challenge_detail", params={"exerciseId": challenge_id}
        )
        if not data:
            return ChallengeInfo(id=challenge_id)
        detail = data.get("data") or data
        parsed = _parse_challenge(detail)
        try:
            self._detail_cache[str(challenge_id)] = (_now, parsed)
        except Exception:  # noqa: BLE001 - 缓存失败不影响
            pass
        return parsed

    async def create_instance(self, challenge_id: str) -> InstanceInfo:
        # 官方 API 文档：body={"exerciseId":1001}
        body = {"exerciseId": int(challenge_id)} if str(challenge_id).isdigit() else {"exerciseId": challenge_id}
        data = await self._request(
            "POST", "build_env", json_body=body
        )
        if not data:
            return InstanceInfo(extra={"challenge_id": challenge_id})
        instance_id = str(data.get("instance_id") or data.get("id") or data.get("data", ""))
        return InstanceInfo(
            instance_id=instance_id,
            status=str(data.get("status", "")),
            extra=data,
        )

    async def get_access(self, instance_id: str, challenge_id: str = "") -> AccessInfo:
        """获取靶机访问地址。优先从 detail 缓存提取 endpoints，无需额外请求。"""
        # P0 修复（2026-08-21 赛中）：DasCTF 靶机地址在 get_challenge 返回的
        # endpoints[].exposeIps[0]（"ip:port"）里，无需 build_env 后再请求；
        # 原实现用错参数（传 instance_id 给需要 exerciseId 的端点），永远取空。
        host, port, url = "", 0, ""
        username, password = "", ""
        entrypoints = []
        data = {}

        # ① 优先从 detail 缓存提取（get_challenge 返回的 endpoints 即真实靶机）
        _cid = str(challenge_id or "")
        try:
            _cache = getattr(self, "_detail_cache", {})
            _cached_ch = None
            if _cid and _cid in _cache:
                _cached_ch = _cache[_cid][1]
            else:
                # 没给题ID时，遍历缓存找第一个有endpoints的（兜底，不推荐）
                for _k, (_ts, _ch) in _cache.items():
                    _eps = (getattr(_ch, "extra", None) or {}).get("endpoints") or []
                    if _eps:
                        _cached_ch = _ch
                        break
            if _cached_ch is not None:
                _eps = (getattr(_cached_ch, "extra", None) or {}).get("endpoints") or []
                for _ep in _eps:
                    if not isinstance(_ep, dict):
                        continue
                    _expose = _ep.get("exposeIps") or []
                    if _expose and isinstance(_expose[0], str):
                        _h, _, _p = str(_expose[0]).partition(":")
                        host = _h
                        try:
                            port = int(_p) if _p else 80
                        except ValueError:
                            port = 80
                        url = f"http://{_expose[0]}"
                        break
                    _ips = _ep.get("proxyIps") or []
                    _ports = _ep.get("ports") or []
                    if _ips:
                        host = str(_ips[0])
                        if _ports:
                            for _pp in _ports:
                                _pp_str = str(_pp)
                                if "/" in _pp_str:
                                    try:
                                        port = int(_pp_str.split("/")[-1])
                                    except ValueError:
                                        pass
                                    break
                        if not port:
                            port = 80
                        url = f"http://{host}" + (f":{port}" if port and port != 80 else "")
                        break
        except Exception:  # noqa: BLE001
            pass

        # ② 缓存未命中时，尝试用 challenge_detail 端点（exerciseId 而非 instance_id）
        if not host:
            try:
                # build_env 返回的 data 里可能含 exerciseId，或 instance_id 本身就是数字题ID
                _eid = instance_id
                data = await self._request("GET", "challenge_detail", params={"exerciseId": _eid})
                if data:
                    detail = data.get("data") or data
                    # 提取 endpoints
                    _eps = detail.get("endpoints") or []
                    if isinstance(_eps, list):
                        for _ep in _eps:
                            if not isinstance(_ep, dict):
                                continue
                            _expose = _ep.get("exposeIps") or []
                            if _expose and isinstance(_expose[0], str):
                                _h, _, _p = str(_expose[0]).partition(":")
                                host = _h
                                try:
                                    port = int(_p) if _p else 80
                                except ValueError:
                                    port = 80
                                url = f"http://{_expose[0]}"
                                break
                            _ips = _ep.get("proxyIps") or []
                            if _ips:
                                host = str(_ips[0])
                                url = f"http://{host}"
                                break
            except Exception:  # noqa: BLE001
                pass

        return AccessInfo(
            host=host,
            port=port,
            username=username,
            password=password,
            url=url,
            entrypoints=entrypoints,
            extra=data,
        )

    async def download_attachment(self, challenge_id: str) -> list[str]:
        # P0 修复（2026-08-21）：优先复用 get_challenge 的 5min TTL 缓存详情，
        # 避免 solver 里刚 get_challenge 完又单独发一次 detail 请求（重复请求=429 源）。
        detail = None
        try:
            detail = await self.get_challenge(challenge_id)
        except Exception:  # noqa: BLE001 - 缓存详情失败则走独立请求
            detail = None
        # 缓存详情里没有附件数据（空 ChallengeInfo）时，才独立再拉一次
        _dextra = (getattr(detail, "extra", None) or {}) if detail is not None else {}
        if detail is None or (not _dextra.get("attachment") and not _dextra.get("attachments")):
            data = await self._request("GET", "challenge_detail", params={"exerciseId": challenge_id})
            if not data:
                return []
            raw_detail = data.get("data") or data
        else:
            raw_detail = _dextra
        # 平台附件字段是 attachment（嵌套对象含 url/name/files）或 attachments
        att = raw_detail.get("attachment") or raw_detail.get("attachments")
        urls = _extract_attachment_urls(att)
        if not urls:
            urls = raw_detail.get("urls") or []
        # P0修复（2026-08-21 17:55）：大文件题（REAL-16/18/20）附件 URL 直接放
        # description 里（https://20260818-atta.dasctf.com/06_mysql_...zip），attachment 为空。
        if not urls:
            _desc = str(raw_detail.get("description") or "")
            _urls = re.findall(r"https?://\S+", _desc)
            urls = [u.rstrip(".,;)]}>\"'") for u in _urls]
        if isinstance(urls, str):
            urls = [urls]
        # P0修复（2026-08-21）：相对URL转绝对URL（平台返回的是/slab-match/...相对路径）
        abs_urls = []
        for u in urls:
            u = str(u)
            if not u:
                continue
            if u.startswith("/"):
                u = self.base_url + u
            elif not u.startswith("http"):
                u = self.base_url + "/" + u
            abs_urls.append(u)
        return abs_urls

    async def download_attachment_bytes(self, url: str) -> bytes:
        """直接下载附件字节（复用平台鉴权头，避免403）。"""
        headers = {"Authorization": self.token} if self.token else {}
        if self.auth_header:
            headers[self.auth_header] = self.token
        # P1-12 修复（2026-08-21 赛后）：复用 AsyncClient（连接池）
        client = self._get_client()
        resp = await client.get(url, headers=headers, follow_redirects=True)
        if resp.status_code == 200:
            return resp.content
        raise RuntimeError(f"附件下载失败 HTTP {resp.status_code}: {resp.text[:200]}")

    async def get_hint(self, challenge_id: str) -> str:
        data = await self._request("POST", "notice_list", json_body={"code": challenge_id})
        if not data:
            return ""
        hint = data.get("hint") or data.get("data") or ""
        return str(hint)

    async def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult:
        # ⚠️ 官方手册第 7 条：「提交时仅需提交 {} 内内容即可」
        # 剥离 flag{...} / DASCTF{...} 外壳，只发花括号内部分。
        # 浪费 50 次/题提交次数 = 直接失去该题得分机会。
        payload_flag = _strip_flag_wrapper(flag)
        # 官方 API 文档：body={"exerciseId":1001,"flag":"example"}，成功 code=="00000" 且 data.isCorrect=true
        # P1-6 修复（2026-08-21 赛后）：int(challenge_id) 加 isdigit 防护（与 create_instance 一致），
        # 非数字 id 不抛 ValueError 中断提交，原样透传。
        _body_exercise_id = int(challenge_id) if str(challenge_id).isdigit() else challenge_id
        data = await self._request(
            "POST", "submit", json_body={"exerciseId": _body_exercise_id, "flag": payload_flag}
        )
        if not data:
            # 第⑥层修复（复盘补遗 2026-08-21）：提交请求层失败（HTTP 4xx/5xx/网络/鉴权）
            # 真实暴露，不再笼统"提交无响应"被吞。标记 request_failed=True，让 poller 熔断
            # 区分"请求故障"与"flag 错误"，避免正确 flag 因平台抖动被静默丢弃（10719 教训）。
            _err = getattr(self, "_last_error", "") or "无错误详情（请求返回空）"
            return SubmitResult(
                accepted=False,
                request_failed=True,
                detail=f"提交请求失败（真实错误）: {_err}",
            )
        ok_code = str(data.get("code", "")) == "00000"
        body = data.get("data") if isinstance(data.get("data"), dict) else {}
        is_correct = bool(body.get("isCorrect") if isinstance(body, dict) else False)
        accepted = ok_code and is_correct
        return SubmitResult(
            accepted=accepted,
            correct=is_correct,
            detail=str(data.get("message") or body.get("message") or ""),
            remaining_attempts=body.get("remainingAttempts") if isinstance(body, dict) else None,
            extra=data,
        )

    async def reset_instance(self, challenge_id: str) -> None:
        """重置/回收题目实例（按exerciseId，不是instanceId）。"""
        if not challenge_id:
            return
        body = {"exerciseId": int(challenge_id)} if str(challenge_id).isdigit() else {"exerciseId": challenge_id}
        try:
            await self._request("POST", "recover_env", json_body=body)
        except Exception:  # noqa: BLE001 - 回收失败不阻塞
            pass

    async def destroy_instance(self, challenge_id: str) -> None:
        """销毁题目实例（同reset_env，平台复用recover端点）。"""
        await self.reset_instance(challenge_id)


# ── 辅助 ─────────────────────────────────────────────────

def _parse_challenge(item: dict) -> ChallengeInfo:
    """把平台返回的题目 dict 解析为 ChallengeInfo（字段兼容多种命名）。"""
    challenge_id = str(item.get("id") or item.get("code") or item.get("challenge_id") or "")
    category_raw = str(item.get("category") or item.get("type") or "").lower()
    # 归一化题型：优先 category/type 字段；列表阶段无该字段时从 title/name 前缀提取
    # （正式赛列表题目形如 "CRYPTO-01"/"PWN-01"/"WEB-01"，category 字段缺失）
    title_raw = str(item.get("title") or item.get("name") or "").lower()
    # 附件名辅助判型：joomla/wordpress/drupal/ghost/cmsms/nginx/httpd/openlitespeed/
    # caddy/openresty/mysql/postgresql/redis → web 源码审计
    att_name = ""
    _att = item.get("attachment")
    if isinstance(_att, dict):
        att_name = str(_att.get("name", "")).lower()
    # P0修复（2026-08-21 17:55）：大文件题附件 URL 在 description 里（attachment 为空），
    # 用 URL 文件名辅助判型（REAL-16/18/20: 06_mysql_.../08_mongodb_.../10_clickhouse_...）
    if not att_name:
        _m = re.search(r"https?://\S+", str(item.get("description") or ""))
        if _m:
            att_name = _m.group(0).split("/")[-1].lower()
    category = "misc"
    # 先从 category/title 前缀匹配
    for cat in ("web", "crypto", "misc", "reverse", "pwn"):
        if cat in category_raw or cat in title_raw:
            category = cat
            break
    # REAL-xx 系列：附件名含 CMS/Web 服务器/数据库名 → web（源码审计类）
    _web_keywords = ("joomla", "wordpress", "drupal", "ghost", "cmsms", "nginx",
                     "httpd", "apache", "openlitespeed", "caddy", "openresty",
                     "mysql", "postgresql", "redis", "mongodb", "clickhouse",
                     "mariadb", "sqlite", "mssql", "oracle", "elasticsearch",
                     "01_", "02_", "03_", "04_", "05_", "06_", "07_", "08_", "09_", "10_")
    if category == "misc" and title_raw.startswith("real-") and any(kw in att_name for kw in _web_keywords):
        category = "web"
    # ── description 兜底（P0 数据链路修复 2026-08-21）──
    # 真实列表接口无 description；详情拉取失败时不能留空题面让 agent 空转。
    # 但"CRYPTO-32"这类纯标识符标题对解题无用且会破坏 no-data 快速止损，
    # 因此只对"描述性标题"（含字母词而非裸题型-编号）兜底。
    _title_full = str(item.get("title") or item.get("name") or "")
    _desc = str(item.get("description") or item.get("desc") or "")
    if not _desc and _title_full and not re.match(
        r"^(web|crypto|misc|reverse|pwn)[-_ ]?\d+$", _title_full, re.IGNORECASE
    ):
        _desc = _title_full
    return ChallengeInfo(
        id=challenge_id,
        title=_title_full or challenge_id,
        category=category,
        description=_desc,
        flag_format=str(item.get("flag_format") or item.get("flag_pattern")
                        or r"flag\{[^}]+\}"),
        score=_safe_int(item.get("score") or item.get("points") or 0),
        has_instance=bool(item.get("has_instance") or item.get("need_instance")
                          or item.get("isNeedInit")
                          or (isinstance(item.get("endpoints"), list) and bool(item.get("endpoints")))),
        has_attachment=bool(
            item.get("has_attachment") or item.get("has_file")
            or bool(item.get("file"))
            or (isinstance(item.get("attachment"), str)
                and bool(str(item.get("attachment", "") or "").strip()))
            or (isinstance(item.get("attachment"), dict)
                and bool(item.get("attachment", {}).get("url")
                         or item.get("attachment", {}).get("downloadUrl")
                         or item.get("attachment", {}).get("src")
                         or item.get("attachment", {}).get("path")
                         or item.get("attachment", {}).get("files")))
            or (isinstance(item.get("attachment"), list) and bool(item.get("attachment")))
            or (isinstance(item.get("attachments"), list) and bool(item.get("attachments")))
            # P0修复（2026-08-21 17:55）：大文件题（REAL-16/18/20）附件 URL 直接放
            # description 里（https://20260818-atta.dasctf.com/06_mysql_...zip），attachment 为空
            or (isinstance(item.get("description"), str)
                and bool(re.search(r"https?://\S+", item.get("description", ""))))
        ),
        extra=item,
    )


def _safe_int(value: Any) -> int:
    """安全转 int（官方 API score 可能返回 '50.0' 字符串）。"""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _extract_attachment_urls(att: Any) -> list:
    """从任意形态的 attachment/attachments 字段提取下载 URL 列表（P0 数据链路修复）。

    兼容形态（真实平台与通用 CTF 平台）：
    - dict: {"url": ...} / {"downloadUrl": ...} / {"src": ...} / {"path": ...}
    - dict: {"files": [{url|downloadUrl|src|path|name}, ...]}
    - list: [{"url": ...}, "https://...", ...]
    - str:  "https://..." / "/slab-match/..."
    """
    urls = []
    if isinstance(att, dict):
        for k in ("url", "downloadUrl", "src", "path", "file_url", "download_url"):
            v = att.get(k)
            if isinstance(v, str) and v.strip():
                urls.append(v.strip())
        files = att.get("files")
        if files is not None and not urls:
            urls.extend(_extract_attachment_urls(files))
    elif isinstance(att, list):
        for a in att:
            if isinstance(a, dict):
                urls.extend(_extract_attachment_urls(a))
            elif isinstance(a, str) and a.strip():
                urls.append(a.strip())
    elif isinstance(att, str) and att.strip():
        urls.append(att.strip())
    return urls


def asyncio_sleep(seconds: float) -> Any:
    """asyncio.sleep 封装（避免模块顶层 import asyncio 干扰）。"""
    import asyncio

    return asyncio.sleep(max(seconds, 0.05))


# ── flag 提交合规：剥离外壳 ─────────────────────────────
import re as _re

_FLAG_WRAPPER_RE = _re.compile(r"^(?:flag|FLAG|ctf|CTF|DASCTF|dasctf)\{(.+)\}$", _re.DOTALL)


def _strip_flag_wrapper(flag: str) -> str:
    """按官方手册要求剥离 flag{}/DASCTF{} 外壳，仅提交 {} 内内容。

    规则（手册第 7 条原文）：
        flag 格式均为 DASCTF{} 或者 flag{}，提交时仅需提交 {} 内内容即可。

    示例：
        "flag{rsa_small_e_2026}" → "rsa_small_e_2026"
        "DASCTF{abc-123}"        → "abc-123"
        "raw_value_no_braces"    → "raw_value_no_braces"（无外壳原样返回）

    特殊格式题（手册说"特殊格式要求将在题目内注明"）：本函数仅剥离标准外壳，
    题目若要求整体提交则应在调用前绕过本函数（暂未遇到此类题）。
    """
    if not flag or not isinstance(flag, str):
        return flag or ""
    f = flag.strip()
    m = _FLAG_WRAPPER_RE.match(f)
    if m:
        inner = m.group(1).strip()
        return inner if inner else f  # 内部为空时回退原值（异常情况）
    return f
