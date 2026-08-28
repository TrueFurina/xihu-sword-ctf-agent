"""web_target_interact skill：靶机 HTTP 000（连接层失败）诊断与交互模板。

真题现象（西湖论剑 2026-08-21 正式赛 Rank-U / 10792）：http_request 返回 status 000，
即 httpx 层在 HTTP 应答前就失败（DNS/拒绝/超时/TLS）。赛后复测 1.14.76.59:15445
http/https 均 WinError 10061（连接拒绝）——与赛中 000 同源，证明「000 不是平台 bug，
是靶机不可达/未就绪」。本题 endpoint 元数据：ports ['http/80'] → proxy 15445。

kind：
- probe:  http/https × GET/HEAD 快速探测，httpx 异常映射为结构化诊断
- retry:  指数退避重试（靶机冷启动/限流场景，建议 attempt=5+）
- fetch:  完整 GET（UA/Accept + 跟随重定向 + verify=False），返回状态/头/正文预览

异常分类（喂给 LLM 的关键结论）：
- dns_fail:      域名解析失败（换 IP 直连）
- conn_refused:  端口拒绝（WinError 10061 / ECONNREFUSED）——服务没起/端口不对
- conn_timeout:  连接超时（WinError 10060 / 无响应）——防火墙丢包/靶机未就绪
- tls_error:     TLS 握手失败（证书/协议）——换 http
- http_ok:       拿到 HTTP 应答（含 4xx/5xx 都算通）

沙盒约束：仅 import httpx（禁 socket/子进程类模块）。
"""

import time


def _classify(exc: Exception, url: str) -> dict:
    """把 httpx 异常映射为结构化诊断。"""
    import httpx
    name = type(exc).__name__
    msg = str(exc)
    low = msg.lower()
    detail = msg[:160]
    # P0 修复（2026-08-28）：默认兜底绝不再把原始异常类名当 verdict 透出——
    # 否则 ConnectionResetError / TimeoutError / 裸 OSError 等未命中上面特定分支时，
    # verdict 会变成 "ConnectionResetError" 之类原始类名，调用方（如 conn_refused
    # 诊断测试）无法识别为故障，导致偶发 flaky 失败。任何 OSError 系（含 socket 错误、
    # ConnectionError 各子类、TimeoutError）一律归连接类诊断。
    verdict = "connect_error" if isinstance(exc, OSError) else "transport_error"
    if isinstance(exc, httpx.ConnectTimeout):
        verdict = "conn_timeout"
    elif isinstance(exc, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        verdict = "conn_timeout"
    elif "10061" in msg or "connection refused" in low or "econnrefused" in low:
        verdict = "conn_refused"
    elif "10060" in msg or "timed out" in low or "timeout" in low:
        verdict = "conn_timeout"
    elif "name or service not known" in low or "getaddrinfo" in low or "nodename" in low:
        verdict = "dns_fail"
    elif isinstance(exc, (httpx.ConnectError,)):
        verdict = "connect_error"
    elif isinstance(exc, httpx.UnsupportedProtocol):
        verdict = "unsupported_protocol"
    elif isinstance(exc, httpx.TransportError):
        verdict = "transport_error"
    # 再保险：未命中特定分支但属 OSError（如 ConnectionResetError / BrokenPipeError）→ 连接错误
    if verdict == "transport_error" and isinstance(exc, OSError):
        verdict = "connect_error"
    if "certificate" in low or "ssl" in low or "tls" in low or "handshake" in low:
        verdict = "tls_error"
    return {"verdict": verdict, "exc_type": name, "detail": detail, "url": url}


def _default_headers() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }


def _proxy_kwargs(params: dict) -> dict:
    """决赛 web 题常需经平台 proxy 端口访问靶机。proxy 非空则注入 httpx proxy（httpx 0.28 起用 proxy= 单参）。"""
    p = params.get("proxy")
    if not p:
        return {}
    return {"proxy": p}


def probe(params: dict) -> dict:
    """http/https × GET/HEAD 快速探测，返回每方案诊断。"""
    import httpx
    url = params.get("url")
    host = params.get("host") or ""
    port = params.get("port") or ""
    schemes = params.get("schemes") or ["http", "https"]
    timeout = float(params.get("timeout", 6))
    headers = {**_default_headers(), **(params.get("headers") or {})}

    candidates = []
    if url:
        candidates.append(url)
    if host:
        for s in schemes:
            candidates.append(f"{s}://{host}" + (f":{port}" if port else "") + "/")
    if not candidates:
        return {"ok": False, "error": "需要 url 或 host"}

    results = []
    for u in candidates:
        methods = ["GET"] if params.get("only_get") else ["GET", "HEAD"]
        for m in methods:
            try:
                t0 = time.time()
                r = httpx.request(m, u, timeout=timeout, verify=False,
                                  follow_redirects=True, headers=headers,
                                  trust_env=False,
                                  **_proxy_kwargs(params))
                results.append({
                    "method": m, "url": str(r.url),
                    "status": r.status_code, "elapsed": round(time.time() - t0, 2),
                    "verdict": "http_ok",
                    "headers": dict(list(r.headers.items())[:8]),
                    "body_preview": _body_preview(r.content, int(params.get("max_body", 300))),
                })
                break  # 该 URL 通了就不用再试另一 method
            except Exception as exc:  # noqa: BLE001
                diag = _classify(exc, u)
                results.append({"method": m, "url": u, "status": 0,
                                "elapsed": round(time.time() - t0, 2), **diag})

    ok = [r for r in results if r.get("verdict") == "http_ok"]
    dead = [r for r in results if r.get("verdict") != "http_ok"]
    verdicts = sorted({r["verdict"] for r in results})
    summary = "通" if ok else "不通"
    return {
        "ok": bool(ok),
        "summary": summary,
        "verdicts": verdicts,
        "results": results[:12],
        "dead_count": len(dead),
        "advice": _advice(verdicts),
    }


def retry(params: dict) -> dict:
    """指数退避重试（靶机冷启动/限流）。"""
    import httpx
    url = params.get("url")
    if not url:
        return {"ok": False, "error": "需要 url"}
    attempts = int(params.get("attempts", 5))
    timeout = float(params.get("timeout", 6))
    base_delay = float(params.get("base_delay", 2.0))
    headers = {**_default_headers(), **(params.get("headers") or {})}
    last = None
    history = []
    for i in range(1, attempts + 1):
        try:
            t0 = time.time()
            r = httpx.get(url, timeout=timeout, verify=False,
                          follow_redirects=True, headers=headers,
                          trust_env=False,
                          **_proxy_kwargs(params))
            history.append({"attempt": i, "status": r.status_code,
                            "elapsed": round(time.time() - t0, 2), "verdict": "http_ok"})
            return {"ok": True, "url": url, "status": r.status_code,
                    "attempts_used": i, "history": history,
                    "headers": dict(list(r.headers.items())[:8]),
                    "body_preview": _body_preview(r.content, int(params.get("max_body", 300)))}
        except Exception as exc:  # noqa: BLE001
            diag = _classify(exc, url)
            history.append({"attempt": i, "status": 0, **diag})
            last = diag
            if i < attempts:
                delay = base_delay * (2 ** (i - 1))
                time.sleep(min(delay, 30))
    return {"ok": False, "url": url, "attempts_used": attempts,
            "history": history, "last": last, "advice": _advice([last["verdict"]])}


def fetch(params: dict) -> dict:
    """完整 GET 抓取：状态码/响应头/正文预览 + flag 线索。"""
    import httpx
    url = params.get("url")
    if not url:
        return {"ok": False, "error": "需要 url"}
    timeout = float(params.get("timeout", 10))
    headers = {**_default_headers(), **(params.get("headers") or {})}
    try:
        t0 = time.time()
        r = httpx.get(url, timeout=timeout, verify=False,
                      follow_redirects=bool(params.get("follow_redirects", True)),
                      headers=headers, trust_env=False,
                      **_proxy_kwargs(params))
        body = r.content
        preview = _body_preview(body, int(params.get("max_body", 600)))
        hints = _flag_hints(body)
        return {
            "ok": True, "url": str(r.url), "status": r.status_code,
            "elapsed": round(time.time() - t0, 2), "content_length": len(body),
            "final_url": str(r.url),
            "headers": dict(list(r.headers.items())[:12]),
            "body_preview": preview,
            "flag_hints": hints,
        }
    except Exception as exc:  # noqa: BLE001
        diag = _classify(exc, url)
        return {"ok": False, "status": 0, **diag}


def _body_preview(content: bytes, max_body: int) -> str:
    if not content:
        return ""
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = content.decode("latin-1", errors="replace")
    return text[:max_body]


def _flag_hints(content: bytes) -> list:
    import re
    pats = [rb"DASCTF\{[^}]{4,64}\}", rb"flag\{[^}]{4,64}\}", rb"ctf\{[^}]{4,64}\}"]
    hits = []
    for p in pats:
        for m in re.finditer(p, content):
            hits.append({"offset": m.start(), "match": m.group().decode(errors="replace")})
    return hits[:10]


def _advice(verdicts: list) -> str:
    tips = []
    if "dns_fail" in verdicts:
        tips.append("DNS 解析失败：用 IP 直连（endpoint 里 exposeIps 通常给 IP:port）")
    if "conn_refused" in verdicts:
        tips.append("连接拒绝（10061）：服务未启动/端口不对——检查 endpoint.portMappings 的 proxy 端口，http 目标别用 https")
    if "conn_timeout" in verdicts:
        tips.append("连接超时：靶机可能还在冷启动——用 retry 指数退避，或检查防火墙/需走代理")
    if "tls_error" in verdicts:
        tips.append("TLS 握手失败：该端口是 http 不是 https，换 http 重试")
    if "http_ok" in verdicts:
        tips.append("HTTP 已通：进入正常 web 交互（目录枚举/源码审计/参数探测）")
    if "unsupported_protocol" in verdicts:
        tips.append("URL 协议写错（如 gopher:// 误用于直连）")
    return "；".join(tips) if tips else ""


def web_target_interact(params: dict) -> dict:
    """skill 入口。"""
    kind = params.get("kind", "probe")
    if kind == "probe":
        return probe(params)
    if kind == "retry":
        return retry(params)
    if kind == "fetch":
        return fetch(params)
    return {"ok": False, "error": f"unknown kind: {kind}",
            "kinds": ["probe", "retry", "fetch"]}


def run(params):
    """SkillManager 统一入口。"""
    return web_target_interact(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="靶机 HTTP 000 诊断与交互")
    parser.add_argument("--kind", default="probe", choices=["probe", "retry", "fetch"])
    parser.add_argument("--url", default="")
    parser.add_argument("--host", default="")
    parser.add_argument("--port", default="")
    parser.add_argument("--attempts", type=int, default=5)
    args = parser.parse_args()
    import json

    params = {"kind": args.kind, "url": args.url, "host": args.host,
              "port": args.port, "attempts": args.attempts}
    print(json.dumps(web_target_interact(params), ensure_ascii=False, indent=1,
                     default=lambda o: o.decode("latin-1") if isinstance(o, bytes) else str(o)))


if __name__ == "__main__":
    main()
