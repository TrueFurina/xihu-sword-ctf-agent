"""PCAP / PCAPNG 流量分析适配器（scapy 2.8.0 主引擎，tshark 可选增强）。

为什么单独一个适配器：REA 6.5.0 的 `inspect-artifact` 完全不吃 pcap，
`rea_probe` 的 lane 嗅探也只会把 pcap 归到 `unknown`。pcap 是 misc 题的高频
载体，必须有自己的通道。

引擎选择（实测，见报告）：
- **scapy 2.8.0** —— 主引擎。纯 Python，零外部依赖，已在项目 venv 内。
  优势是**字节级可控**：TCP 重组、任意偏移切片、自定义启发式都能直接实现。
- **tshark** —— 可选增强。若 `TSHARK_BIN` 指向可执行文件则额外采信它的
  协议层次统计（dissector 覆盖几百种协议，scapy 比不了）。**不作必需依赖**：
  装不上也必须能跑。

一条必须写进契约的事实：**跨 TCP 段的正文是按 seq 重建的，不是抓包顺序**。
CTF 里的 flag 经常被拆在相邻两个包里（本适配器的测试样本就是），不重组必然漏。

不做的事：不解密 TLS（没有 keylog）、不还原被压缩的 gzip 正文、
不做动态协议逆向。加密流量只能给 SNI/证书名这类元数据。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import zlib
from collections import Counter, defaultdict

from tools.base import ToolAdapter, ToolOutput
# 复用 rea_probe 的契约/flag/置信分级，保持三个适配器同一套语义。
# 顶层导入而非函数内局部导入：局部导入不会成为模块属性，测试与外部调用
# 都无法直接验证这些函数（实测踩到，`pcap_probe._flags_in` 直接 AttributeError）。
# rea_probe 不反向依赖本模块，不存在循环导入。
from tools.adapters.rea_probe import _contract, _flags_in, _plausibility

logger = logging.getLogger(__name__)

#: tshark 路径（可选；存在才启用）
_DEFAULT_TSHARK = os.environ.get("TSHARK_BIN", r"E:\Program\tools\wireshark-portable\tshark.exe")
_TSHARK = os.environ.get("TSHARK_BIN", _DEFAULT_TSHARK)
_TIMEOUT = int(os.environ.get("PCAP_TIMEOUT", "180"))

#: 解析包数上限。scapy 逐包解析约 6k 包/秒
_MAX_PACKETS = int(os.environ.get("PCAP_MAX_PACKETS", "2000000"))
#: 墙钟时间预算（秒）。无论多少包，超时即停并如实标注截断。
#: 为什么要有它：profile 显示 67% 时间花在 scapy 自己的 dissect 上，
#: 优化本适配器代码最多只能省 4%。与其冒险重写解析器，不如保证「不会卡死」。
_DEADLINE = float(os.environ.get("PCAP_DEADLINE", "120"))
#: 单条流保留下来的字节上限（超出截断，flag 裸扫只覆盖前 N 字节）
_MAX_FLOW_BYTES = int(os.environ.get("PCAP_MAX_FLOW_BYTES", str(8 * 1024 * 1024)))
#: 全部流累计内存上限，防止 pcap 撑爆内存
_MAX_TOTAL_BYTES = int(os.environ.get("PCAP_MAX_TOTAL_BYTES", str(192 * 1024 * 1024)))
#: 回给 LLM 的正文预览长度
_PREVIEW = int(os.environ.get("PCAP_PREVIEW", "600"))

_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap/LE",
    b"\xa1\xb2\xc3\xd4": "pcap/BE",
    b"\x4d\x3c\xb2\xa1": "pcap-ns/LE",
    b"\xa1\xb2\x3c\x4d": "pcap-ns/BE",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}

#: HTTP 起始行
_HTTP_REQ = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP/(\d\.\d)")
_HTTP_RESP = re.compile(rb"^HTTP/(\d\.\d) (\d{3}) ?([^\r\n]*)")
#: 明文凭据线索（表单 / header / JSON 都覆盖）
_CRED_RE = re.compile(
    rb"(?i)\b(user(?:name)?|pass(?:word|wd)?|pwd|token|api[_-]?key|secret|auth(?:orization)?)"
    rb"\s*[=:]\s*([^\s&;\"'<>\r\n]{1,80})")
_BASIC_RE = re.compile(rb"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})")
#: TLS ClientHello 的 SNI。结构是
#:   00 00 <ext_len:2> <server_name_list_len:2> 00 <name_len:2> <name>
#: 四个捕获组依次为 ext_len / list_len / name_len / name_bytes。
#: 早先写成三个 `(..)` 却取 group(5)，实测直接 IndexError 把整条链打断。
_SNI_RE = re.compile(rb"\x00\x00(..)(..)\x00(..)([\x20-\x7e]{3,120})", re.S)


def _safe(b: bytes, limit: int = 120) -> str:
    """把二进制片段变成可安全放进日志/正文的单行文本。"""
    s = b.decode("latin-1", errors="replace")
    s = re.sub(r"[^\x20-\x7e]", ".", s)
    return s[:limit]


def _safe_multiline(b: bytes, limit: int = 400) -> str:
    """同 _safe，但保留换行——HTTP 正文预览需要看得出结构，全压成一行会丢信息。"""
    s = b.decode("latin-1", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[^\x20-\x7e\n]", ".", s)
    return s.rstrip()[:limit]


def _fmt_ts(ts: float) -> str:
    """Unix 时间戳 → 本地可读时间。失败就返回原始值，不抛异常。"""
    try:
        import datetime
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:  # noqa: BLE001
        return f"{ts:.3f}"


def _looks_like_pcap(head: bytes) -> str | None:
    for magic, name in _MAGICS.items():
        if head.startswith(magic):
            return name
    return None


def _flow_key(a: tuple, b: tuple) -> tuple:
    """双向归一到同一个 key，保证请求/响应落在同一流。"""
    return (a, b) if a <= b else (b, a)


def _reassemble(segs: list[tuple[int, bytes]]) -> tuple[bytes, list[tuple[int, int]], int]:
    """按 TCP seq 把分段拼成连续字节流。

    Returns: (data, gaps, overlap_bytes)
      - gaps: [(相对偏移, 缺口长度)]，缺口用 \\x00 占位填平（保持后续偏移可算）
      - overlap_bytes: 被重叠覆盖掉的字节数（重传）

    为什么自己写而不用 scapy 的 TCPSession：TCPSession 会按流返回合成的包，
    拿不到「缺口位置」这类诊断信息，而缺口恰好是判断「重组是否可信」的关键。
    """
    if not segs:
        return b"", [], 0
    segs = sorted(segs, key=lambda x: x[0])
    base = segs[0][0]
    out = bytearray()
    cur = base
    gaps: list[tuple[int, int]] = []
    overlap = 0
    for seq, payload in segs:
        off = seq - cur
        if off < 0:                      # 与已写内容重叠（重传）
            skip = -off
            if skip >= len(payload):
                overlap += len(payload)
                continue
            overlap += skip
            payload = payload[skip:]
            off = 0
        if off > 0:                      # 缺包
            gaps.append((cur - base, off))
            out.extend(b"\x00" * off)
            cur += off
        out.extend(payload)
        cur += len(payload)
    return bytes(out), gaps, overlap


#: 解压上限：防压缩炸弹（真实抓包里见过 1KB → 数百 MB 的 gzip）
_MAX_INFLATE = 8 * 1024 * 1024


def _inflate(raw: bytes, encoding: str = "") -> tuple[bytes, str]:
    """按 Content-Encoding 解压正文；失败原样返回并写明原因（不假装修好了）。

    2026-10-20 由真实抓包触发：Wireshark 官方 `http.cap` 里一个 1272 B 的响应
    标着 `text/html`，实际是 deflate 压缩，原样打印是一屏乱码。合成样本里我写的
    都是明文正文，所以此前从未测到。CTF 的 flag 很常藏在这种压缩正文里。

    2026-10-20 二次扩容：`br`（Brotli）与 `zstd` 是现代站点的常规编码，旧实现
    对这两种**连提示都不给**（`br` 既不命中 gzip/deflate 关键词、也无魔数），
    正文被当成明文塞进上下文 —— 读起来是乱码，却没有任何「这是压缩态」的标记，
    比明确报错更危险。现在按 `Content-Encoding` 逐个解码（支持 `gzip, br` 这种
    多段编码，按规范的逆序还原），不认识的编码一律留痕。

    Returns:
        (正文, 说明)。说明为空表示没做任何处理。
    """
    if not raw:
        return raw, ""
    enc = (encoding or "").strip().lower()
    encs = [e.strip() for e in enc.split(",") if e.strip()]
    # 头里没写编码时靠魔数兜底：真实抓包里见过声明 text/html、实际是 deflate 的响应
    if not encs:
        if raw[:2] == b"\x1f\x8b":
            encs = ["gzip"]
        elif raw[:4] == b"\x28\xb5\x2f\xfd":
            encs = ["zstd"]
        elif len(raw) > 2 and raw[0] == 0x78:
            encs = ["deflate"]
        else:
            return raw, ""
    data, notes = raw, []
    for e in reversed(encs):          # 编码按应用顺序声明，解码要逆序
        data, note = _decode_one(data, e)
        if note:
            notes.append(note)
        if note.startswith(_STUCK_PREFIX):
            break                     # 这一层没解开，再套下一层没有意义
    return data, "；".join(notes)


def _decode_one(raw: bytes, enc: str) -> tuple[bytes, str]:
    """解一层编码。返回 (正文, 说明)；解不开就原样退回并说明原因。"""
    if enc in ("identity", ""):
        return raw, ""
    if enc in ("gzip", "x-gzip"):
        return _zlib_like(raw, 31, "gzip")      # 31 = 自动识别 gzip 头
    if enc == "deflate":
        out, note = _zlib_like(raw, 15, "zlib")  # 规范要求 zlib 包装
        if note.startswith("解压失败"):
            out, note = _zlib_like(raw, -15, "deflate-raw")   # 但现实里常是裸 deflate
        return out, note
    if enc == "br":
        try:
            import brotli  # 延迟导入：缺库只降级，不拖垮整个通道
        except ImportError:
            return raw, "库缺失（brotli 未安装），正文仍是 br 压缩态"
        dec, out, step = brotli.Decompressor(), bytearray(), 64 * 1024
        try:
            # 一次性 decompress() 没有输出上限，压缩炸弹能直接吃满内存，
            # 所以按块喂流式解压器，超限立刻停。
            for i in range(0, len(raw), step):
                out.extend(dec.process(raw[i:i + step]))
                if len(out) > _MAX_INFLATE:
                    return bytes(out[:_MAX_INFLATE]), f"br 已解压，超 {_MAX_INFLATE // 1048576}MB 截断"
        except Exception:  # noqa: BLE001 - 载荷损坏会抛，已解出的部分仍有价值
            if out:
                return bytes(out), "解压不完整（br，载荷损坏）"
            return raw, "解压失败（br，正文可能被截断）"
        # 关键：stream 没报错 != 解完了。截断的 br 会安静地吐出半截正文
        # （实测截掉尾部 4 字节仍返回前 30 字节），必须靠 is_finished() 判完整。
        if not dec.is_finished():
            return bytes(out), "解压不完整（br，正文被截断）"
        return bytes(out), "br 已解压"
    if enc in ("zstd", "x-zstd"):
        try:
            import io

            import zstandard  # 可选依赖
        except ImportError:
            return raw, "库缺失（zstandard 未安装），正文仍是 zstd 压缩态"
        out, broken = bytearray(), False
        try:
            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw),
                                                            read_across_frames=True) as rd:
                while len(out) <= _MAX_INFLATE:
                    chunk = rd.read(256 * 1024)
                    if not chunk:
                        break
                    out.extend(chunk)
        except Exception:  # noqa: BLE001 - 截断帧/损坏：保留已解出部分
            broken = True
        if len(out) > _MAX_INFLATE:
            return bytes(out[:_MAX_INFLATE]), f"zstd 已解压，超 {_MAX_INFLATE // 1048576}MB 截断"
        if not out:
            return raw, "解压失败（zstd，正文可能被截断）"
        if broken:
            return bytes(out), "解压不完整（zstd，载荷损坏或截断）"
        # 最后一道闸：帧头里写了原始长度时对账。实测截断的 zstd 在 stream_reader
        # 下**不一定抛异常**（30 字节的载荷截掉 4 字节时它安静返回 31 字节、无错），
        # 只凭「没抛异常」会把它当完整解压。
        try:
            declared = zstandard.frame_content_size(raw)
        except Exception:  # noqa: BLE001 - 读不到就当未知
            declared = -1
        if 0 <= declared and len(out) < declared:
            return bytes(out), f"解压不完整（zstd，声明 {declared} B 只解出 {len(out)} B）"
        return bytes(out), "zstd 已解压"
    return raw, f"未支持编码 {enc}，正文仍是压缩态"


def _zlib_like(raw: bytes, wbits: int, tag: str) -> tuple[bytes, str]:
    """gzip/deflate 通用解压：输出有上限，截断时保留已解出的部分。

    旧实现用 `gzip.decompress()` 一把梭，正文被截断就整块丢弃并退回压缩态 ——
    而 CTF 抓包里「流被截断」是常态，等于把还在画面里的 flag 一起扔掉。
    """
    dec = zlib.decompressobj(wbits)
    try:
        out = dec.decompress(raw, _MAX_INFLATE)
    except zlib.error:
        return raw, f"解压失败（{tag}）"
    if dec.unconsumed_tail:
        return out[:_MAX_INFLATE], f"{tag} 已解压，超 {_MAX_INFLATE // 1048576}MB 截断"
    if not dec.eof:                       # 输入没读完 => 流被截断
        if out:
            return out, f"解压不完整（{tag}，正文被截断）"
        return raw, f"解压失败（{tag}，正文被截断）"
    return out, f"{tag} 已解压"


#: 这些说明意味着「正文没完整还原」，要计入 degraded，不能当没发生
_STUCK_PREFIX = ("解压失败", "解压不完整", "未支持编码", "库缺失")


def _looks_text(b: bytes) -> bool:
    """粗略判断是否为可读文本：不可读时不要往上下文里灌一屏点号。"""
    if not b:
        return True
    sample = b[:512]
    bad = sum(1 for x in sample if x < 9 or 13 < x < 32)
    return bad / len(sample) < 0.05


def _split_http(data: bytes) -> list[dict]:
    """从一个方向的流数据里切出 HTTP 消息（尽力而为，解析失败不影响主流程）。

    返回 [{kind, line, method, target, status, headers, body, offset}]。
    对 Content-Length 与 chunked 都做处理；两者都对不上时按「读到结尾」处理，
    宁可多给也不要漏 —— CTF 里漏正文等于丢 flag。
    """
    msgs: list[dict] = []
    i, n = 0, len(data)
    guard = 0
    while i < n and guard < 5000:
        guard += 1
        m_req = _HTTP_REQ.match(data, i)
        m_resp = _HTTP_RESP.match(data, i)
        if not (m_req or m_resp):
            # 不是消息起点，往后找下一个可能的边界
            nxt = min([p for p in (data.find(b"GET ", i + 1), data.find(b"POST ", i + 1),
                                  data.find(b"HTTP/1.", i + 1)) if p > 0], default=-1)
            if nxt < 0:
                break
            i = nxt
            continue
        hdr_end = data.find(b"\r\n\r\n", i)
        if hdr_end < 0:
            break
        head = data[i:hdr_end]
        hdrs: dict[str, str] = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                hdrs[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
        body_start = hdr_end + 4
        body = b""
        if m_req:
            kind = "req"
            clen = int(hdrs.get("content-length") or 0) if hdrs.get("content-length", "").isdigit() else 0
            body = data[body_start:body_start + clen]
            body, enc_note = _inflate(body, hdrs.get("content-encoding", ""))
            nxt_i = body_start + clen
            msgs.append({"kind": kind, "method": m_req.group(1).decode(), "target": _safe(m_req.group(2), 200),
                         "status": None, "headers": hdrs, "body": body, "enc_note": enc_note, "offset": i})
        else:
            kind = "resp"
            status = int(m_resp.group(2))
            clen_s = hdrs.get("content-length")
            chunked = "chunked" in (hdrs.get("transfer-encoding") or "").lower()
            if chunked:
                body, consumed = _dechunk(data[body_start:])
                nxt_i = body_start + consumed
            elif clen_s and clen_s.isdigit():
                clen = int(clen_s)
                body = data[body_start:body_start + clen]
                nxt_i = body_start + clen
            else:
                body = data[body_start:]
                nxt_i = n
            # Content-Encoding 在 Transfer-Encoding 之后作用于实体正文，
            # 所以解压必须放在 chunked 拆分之后（顺序错了会解不出来）
            body, enc_note = _inflate(body, hdrs.get("content-encoding", ""))
            msgs.append({"kind": kind, "method": None, "target": None, "status": status,
                         "headers": hdrs, "body": body, "enc_note": enc_note, "offset": i})
        if nxt_i <= i:
            break
        i = nxt_i
    return msgs


def _dechunk(data: bytes) -> tuple[bytes, int]:
    """解 chunked 编码，返回 (正文, 消耗字节数)。格式不对就原样返回。"""
    out = bytearray()
    i = 0
    try:
        while i < len(data):
            eol = data.find(b"\r\n", i)
            if eol < 0:
                break
            size_s = data[i:eol].split(b";")[0].strip()
            size = int(size_s, 16)
            if size == 0:
                end = data.find(b"\r\n\r\n", eol)
                i = (end + 4) if end > 0 else eol + 4
                return bytes(out), i
            out.extend(data[eol + 2:eol + 2 + size])
            i = eol + 2 + size + 2
    except (ValueError, IndexError):
        return data, len(data)
    return bytes(out), i or len(data)


def _sni_of(payload: bytes) -> str | None:
    """从 TLS ClientHello 里取 SNI。取不到返回 None（不猜）。

    用 name_len 与实际长度交叉校验：只有「声明长度 == 匹配到的域名字符数」
    才采信，避免把 random 里的裸 `00 00` 误当扩展起点。
    """
    if not payload or payload[0] != 0x16:
        return None
    for m in _SNI_RE.finditer(payload):
        name_len = int.from_bytes(m.group(3), "big")
        if not 3 <= name_len <= 120:
            continue
        raw = m.group(4)
        if len(raw) < name_len:
            continue
        cand = raw[:name_len].decode("latin-1", errors="replace")
        if re.fullmatch(r"[A-Za-z0-9.\-_]{3,120}", cand) and "." in cand:
            return cand
    return None


def _tshark_hierarchy(path: str) -> tuple[str, str]:
    """用 tshark 拿协议层次统计。返回 (正文, 错误说明)。"""
    if not os.path.isfile(_TSHARK):
        return "", f"tshark 未安装（{_TSHARK}）"
    try:
        p = subprocess.run(
            [_TSHARK, "-r", path, "-q", "-z", "io,phs"],
            capture_output=True, timeout=_TIMEOUT,
            encoding="utf-8", errors="replace",
        )
        if p.returncode != 0:
            return "", f"tshark rc={p.returncode}: {_safe((p.stderr or '').encode('utf-8','replace'), 160)}"
        return p.stdout or "", ""
    except subprocess.TimeoutExpired:
        return "", f"tshark 超时 {_TIMEOUT}s"
    except Exception as exc:  # noqa: BLE001
        return "", f"{type(exc).__name__}: {exc}"


class PcapProbeAdapter(ToolAdapter):
    """PCAP/PCAPNG 流量分析：协议统计 + TCP 重组 + HTTP/DNS/TLS 提取 + flag 定位。"""

    name = "pcap_probe"
    categories = ["misc", "forensics", "web"]
    #: plan 可透传参数（主链按此白名单转发，见 core/action_executor.py）
    param_spec = {
        "flow": "只输出该流号的全文（先无参调用拿流表）",
        "top_n": "最多列几条（默认 15）",
        "max_packets": "解析包数上限（默认 200 万）",
    }

    @property
    def description(self) -> str:
        return (
            "PCAP/PCAPNG 流量分析（scapy 主引擎，tshark 可选增强）：协议分布、双向流表、"
            "TCP 按 seq 重组、HTTP 请求/响应正文提取、DNS 查询、TLS SNI、明文凭据线索，"
            "并把 flag 候选定位到「第几个包 / 第几条流」。传 path=抓包文件；"
            "可选 top_n=流表条数(默认15)、flow=流号(取该流完整内容)、"
            "max_packets=解析上限。跨段正文为重组结果，非抓包顺序。"
        )

    async def run(self, params: dict) -> ToolOutput:
        path = str(params.get("path") or params.get("file") or "")
        if not path or not os.path.isfile(path):
            return ToolOutput(
                text=f"[pcap_probe] 目标不存在：{path or '(空)'}（not_applicable）",
                ok=False,
            )
        try:
            top_n = int(params.get("top_n") or 15)
        except (TypeError, ValueError):
            top_n = 15
        flow = params.get("flow")
        try:
            max_pkts = int(params.get("max_packets") or _MAX_PACKETS)
        except (TypeError, ValueError):
            max_pkts = _MAX_PACKETS
        try:
            return await asyncio.to_thread(self._run_sync, path, top_n, flow, max_pkts)
        except Exception as exc:  # noqa: BLE001 - 适配器不因单个样本崩掉整条链
            logger.exception("pcap_probe 失败")
            return ToolOutput(text=f"[pcap_probe] 解析异常：{type(exc).__name__}: {exc}", ok=False)

    # ── 主流程 ───────────────────────────────────────────

    def _run_sync(self, path: str, top_n: int, flow, max_pkts: int) -> ToolOutput:
        with open(path, "rb") as f:
            head = f.read(64)
        fmt = _looks_like_pcap(head)
        size = os.path.getsize(path)
        if not fmt:
            return ToolOutput(
                text=(f"[pcap_probe] {os.path.basename(path)} 不是 pcap/pcapng"
                      f"（首 4 字节 {head[:4].hex()}）；pcap 需 magic d4c3b2a1 / 0a0d0d0a 等"),
                raw=json.dumps(_contract(
                    authority="unknown", status="not_applicable",
                    limitations=["文件头不是 pcap/pcapng magic"]), ensure_ascii=False),
                ok=False,
            )

        try:
            from scapy.all import PcapReader, Raw, TCP, UDP, IP, IPv6, DNS  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            return ToolOutput(
                text=f"[pcap_probe] scapy 不可用：{exc}；pip install scapy 后重试",
                ok=False,
            )

        pkt_total = 0
        pkt_bytes = 0
        first_ts = last_ts = None
        trunc_reason = ""
        proto_counter: Counter = Counter()
        # 流：key -> {"ends": (a,b), "dir": {a: [(seq,payload)], b: [...]}, "pkts": int, "bytes": int}
        flows: dict[tuple, dict] = {}
        dns_q: list[tuple[str, int]] = []
        sni_list: list[tuple[str, int]] = []
        pkt_hits: dict[str, set[int]] = defaultdict(set)
        truncated = False
        total_held = 0

        import time as _time
        t_start = _time.monotonic()

        try:
            with PcapReader(path) as reader:
                for pkt in reader:
                    pkt_total += 1
                    if pkt_total > max_pkts:
                        truncated = True
                        trunc_reason = f"达到包数上限 max_packets={max_pkts:,}"
                        break
                    # 每 256 包查一次墙钟，避免每包都 syscall
                    if (pkt_total & 0xFF) == 0 and _time.monotonic() - t_start > _DEADLINE:
                        truncated = True
                        trunc_reason = f"达到时间预算 {_DEADLINE:.0f}s（已解析 {pkt_total:,} 包）"
                        break
                    try:
                        ts = float(pkt.time)
                        if first_ts is None:
                            first_ts = ts
                        last_ts = ts
                    except Exception:  # noqa: BLE001
                        pass

                    # 协议分布：取层次类名（scapy 已解析的部分）
                    try:
                        names = [lay.__name__ for lay in pkt.layers()]
                    except Exception:  # noqa: BLE001
                        names = []
                    for nm in names:
                        proto_counter[nm] += 1

                    # 包级 payload 裸扫（能定位到具体包号）
                    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
                    if payload:
                        pkt_bytes += len(payload)
                        # 预筛：三条 FLAG 正则全部形如 `xxx{...}`，不含 `{` 的载荷
                        # 不可能命中。这一层把 200 万包场景的正则开销从「每包一次」
                        # 降到「只有带 { 的包才跑」，实测是数量级差异。
                        if b"{" in payload:
                            for cand in _flags_in([payload.decode("latin-1", errors="replace")]):
                                pkt_hits[cand].add(pkt_total)

                    # DNS 查询名（qd 可能是链，也可能是 NoPayload；用 guard 防环）
                    if DNS in pkt:
                        try:
                            q = pkt[DNS].qd
                            guard = 0
                            while q is not None and guard < 20:
                                guard += 1
                                nm = getattr(q, "qname", None)
                                if nm is None:
                                    break
                                nm = (nm.decode("latin-1", errors="replace")
                                      if isinstance(nm, bytes) else str(nm)).rstrip(".")
                                if nm and nm != ".":
                                    dns_q.append((nm, pkt_total))
                                nxt = getattr(q, "payload", None)
                                if nxt is None or nxt.__class__.__name__ == "NoPayload":
                                    break
                                q = nxt
                        except Exception:  # noqa: BLE001
                            pass

                    # TLS SNI
                    if payload and payload[:1] == b"\x16":
                        sni = _sni_of(payload)
                        if sni:
                            sni_list.append((sni, pkt_total))

                    # TCP 流归集
                    if TCP in pkt:
                        try:
                            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
                            if ip is None:
                                continue
                            a = (str(ip.src), int(pkt[TCP].sport))
                            b = (str(ip.dst), int(pkt[TCP].dport))
                            key = _flow_key(a, b)
                            st = flows.setdefault(key, {"ends": key, "dir": {}, "pkts": 0,
                                                        "bytes": 0, "proto": "TCP"})
                            st["pkts"] += 1
                            if payload:
                                # SYN 占 1 个序号，数据起点是 seq+1
                                seq = int(pkt[TCP].seq) + (1 if payload else 0)
                                d = st["dir"].setdefault(a, [])
                                st["bytes"] += len(payload)
                                if total_held < _MAX_TOTAL_BYTES and st["bytes"] <= _MAX_FLOW_BYTES * 2:
                                    d.append((seq, payload))
                                    total_held += len(payload)
                            # SYN 记录 ISN，供相对偏移计算
                            if pkt[TCP].flags & 0x02 and not payload:
                                st.setdefault("isn", {})[a] = int(pkt[TCP].seq)
                        except Exception:  # noqa: BLE001
                            continue
                    elif UDP in pkt:
                        try:
                            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
                            if ip is None:
                                continue
                            a = (str(ip.src), int(pkt[UDP].sport))
                            b = (str(ip.dst), int(pkt[UDP].dport))
                            key = _flow_key(a, b)
                            st = flows.setdefault(key, {"ends": key, "dir": {}, "pkts": 0,
                                                        "bytes": 0, "proto": "UDP"})
                            st["pkts"] += 1
                        except Exception:  # noqa: BLE001
                            continue
        except Exception as exc:  # noqa: BLE001
            return ToolOutput(
                text=f"[pcap_probe] 读取失败：{type(exc).__name__}: {exc}",
                ok=False,
            )

        # ── 重组 + HTTP 提取 + 流级 flag 裸扫 ─────────────
        flow_ids = sorted(flows.keys(), key=lambda k: -flows[k]["bytes"])
        flow_index = {k: i for i, k in enumerate(flow_ids)}
        http_msgs: list[dict] = []
        flow_hits: dict[str, set[int]] = defaultdict(set)
        decoded_hits: set[str] = set()      # 只出现在解压后正文里的候选
        creds: list[tuple[str, int]] = []
        reassembled: dict[int, dict] = {}

        for key in flow_ids:
            st = flows[key]
            if not st["dir"]:
                continue
            fid = flow_index[key]
            per_dir: dict[tuple, bytes] = {}
            gaps_all: list[tuple[int, int]] = []
            for end, segs in st["dir"].items():
                data, gaps, ov = _reassemble(segs)
                per_dir[end] = data
                gaps_all.extend(gaps)
                if gaps or ov:
                    reassembled.setdefault(fid, {})[end] = {"gaps": gaps, "overlap": ov}
            merged = b"\x00".join(per_dir.values()) if len(per_dir) > 1 else (next(iter(per_dir.values())) if per_dir else b"")
            # 流级裸扫（覆盖被拆到多段的 flag）
            if b"{" in merged:
                for cand in _flags_in([merged.decode("latin-1", errors="replace")]):
                    flow_hits[cand].add(fid)
            # HTTP 解析（每个方向独立）
            for end, data in per_dir.items():
                for msg in _split_http(data):
                    msg["flow"] = fid
                    msg["from_end"] = end
                    http_msgs.append(msg)
                    # 解压后的正文必须重新扫：流级裸扫看的是**压缩态**字节，
                    # flag 藏在 br/gzip 正文里时它一个字符都匹配不到。而正文预览
                    # 只渲染前 300 B，超出预览的 flag 就彻底消失（真实 http.cap
                    # 解压后 3608 B，flag 完全可能在后半段）。
                    if "已解压" in (msg.get("enc_note") or ""):
                        for cand in _flags_in([msg["body"].decode("latin-1", errors="replace")]):
                            flow_hits[cand].add(fid)
                            decoded_hits.add(cand)
                    # 凭据线索：header 里的 Authorization + body 里的表单/JSON
                    blob = (b" ".join(f"{k}: {v}".encode() for k, v in msg["headers"].items())
                            + b" " + msg["body"][:4096])
                    for m in _BASIC_RE.finditer(blob):
                        creds.append((f"Authorization: Basic {_safe(m.group(1), 40)}", fid))
                    for m in _CRED_RE.finditer(blob):
                        val = m.group(2)
                        if val and not val.startswith((b"$", b"{", b"%")) and len(val) >= 3:
                            creds.append((f"{m.group(1).decode('latin-1')}={_safe(val, 60)}", fid))

        # ── 组装输出 ─────────────────────────────────────
        lines: list[str] = []
        span = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else None
        lines.append(f"[pcap_probe] {os.path.basename(path)}  ({fmt}, {size:,} B)")
        span_s = f"，跨度 {span:.2f}s" if span is not None else ""
        lines.append(f"  包 {pkt_total:,} / 流 {len(flows):,} / 载荷 {pkt_bytes:,} B{span_s}"
                     + (f"（⚠ 已截断：{trunc_reason}，不是全集）" if truncated else ""))
        if first_ts is not None:
            lines.append(f"  起点 {_fmt_ts(first_ts)}"
                         + (f" → {_fmt_ts(last_ts)}" if last_ts and last_ts != first_ts else ""))

        # 网络/传输层协议（scapy 解析出的层）
        skip = {"Ether", "IP", "IPv6", "Raw", "Padding", "NoPayload", "CookedLinux"}
        net_protos = [f"{k}×{v}" for k, v in proto_counter.most_common() if k not in skip and v]
        if net_protos:
            lines.append("  协议层：" + "  ".join(net_protos[:12]))
        protos_present = ", ".join(f"{k}({v})" for k, v in proto_counter.most_common() if k not in skip)

        # 应用层（scapy 不建层，靠内容识别）—— 与上面的计数语义不同，必须分开写，
        # 否则「HTTP×4」会被误读成「4 个 HTTP 包」（实际是 4 条消息）
        app = []
        if http_msgs:
            app.append(f"HTTP({len([m for m in http_msgs if m['kind']=='req'])} 请求"
                       f"/{len([m for m in http_msgs if m['kind']=='resp'])} 响应)")
        if sni_list:
            app.append(f"TLS({len(sni_list)} ClientHello)")
        if dns_q:
            app.append(f"DNS({len(dns_q)} 查询)")
        if app:
            lines.append("  应用层：" + "  ".join(app))

        # flag 候选：包级 + 流级合并，用 _flags_in 的吞并逻辑去重
        all_cands = sorted(set(pkt_hits) | set(flow_hits))
        flags = _flags_in(all_cands) if all_cands else []
        if flags:
            lines.append("")
            lines.append(f"  ★ flag 候选（{len(flags)}，按可信度排序）")
            ranked = sorted(flags, key=lambda x: (0 if _plausibility(x) == "★" else 1, -len(x)))
            for f in ranked[:8]:
                src = []
                if f in flow_hits:
                    src.append("流 #" + ",".join(str(i) for i in sorted(flow_hits[f])[:3]))
                if f in pkt_hits:
                    src.append("包 #" + ",".join(str(i) for i in sorted(pkt_hits[f])[:3]))
                if f in decoded_hits:
                    src.append("解压后正文")
                lines.append(f"    {_plausibility(f)}  {f}    ← {' / '.join(src) or '?'}")

        # 流表
        lines.append("")
        lines.append(f"  流表（按字节数降序，前 {min(top_n, len(flow_ids))}/{len(flow_ids)}）")
        for key in flow_ids[:top_n]:
            st = flows[key]
            fid = flow_index[key]
            a, b = st["ends"]
            label = ""
            if fid in reassembled:
                gp = sum(g[1] for d in reassembled[fid].values() for g in d["gaps"])
                ov = sum(d["overlap"] for d in reassembled[fid].values())
                if gp:
                    label += f"  ⚠缺口 {gp}B"
                if ov:
                    label += f"  ↺重传 {ov}B"
            if any(m["flow"] == fid for m in http_msgs):
                label += "  HTTP"
            lines.append(f"    #{fid}  {st['proto']} {a[0]}:{a[1]} ↔ {b[0]}:{b[1]}"
                         f"   {st['pkts']} 包 / {st['bytes']:,} B{label}")

        # DNS
        if dns_q:
            uniq = []
            seen = set()
            for nm, pi in dns_q:
                if nm not in seen:
                    seen.add(nm)
                    uniq.append((nm, pi))
            lines.append("")
            lines.append(f"  DNS 查询（{len(uniq)} 个唯一名）")
            for nm, pi in uniq[:12]:
                lines.append(f"    {nm}    ← 包 #{pi}")

        # TLS SNI
        if sni_list:
            lines.append("")
            lines.append(f"  TLS SNI（{len(sni_list)}）")
            for nm, pi in sni_list[:10]:
                lines.append(f"    {nm}    ← 包 #{pi}")
            lines.append("    （TLS 正文加密，未提供 keylog 时不可解）")

        # 明文凭据
        if creds:
            uniq_c = []
            seen_c = set()
            for c, fid in creds:
                if c not in seen_c:
                    seen_c.add(c)
                    uniq_c.append((c, fid))
            lines.append("")
            lines.append(f"  明文凭据线索（{len(uniq_c)}）")
            for c, fid in uniq_c[:10]:
                lines.append(f"    {c}    ← 流 #{fid}")

        # HTTP
        reqs = [m for m in http_msgs if m["kind"] == "req"]
        resps = [m for m in http_msgs if m["kind"] == "resp"]
        # 正文没还原出来的那些必须单列：它们看起来「没有 flag」，实际是没解开
        stuck = [m for m in http_msgs
                 if (m.get("enc_note") or "").startswith(_STUCK_PREFIX)]
        if reqs or resps:
            lines.append("")
            lines.append(f"  HTTP：{len(reqs)} 请求 / {len(resps)} 响应")
            for m in reqs[:12]:
                host = m["headers"].get("host", "")
                lines.append(f"    {m['method']} {m['target']}    Host: {host}    ← 流 #{m['flow']}")
            # 有正文的响应给预览（flag 最常藏在这里）
            bodies = [m for m in resps if m["body"]]
            if bodies:
                lines.append(f"  响应正文预览（{len(bodies)} 条有正文，按长度降序前 5）")
                for m in sorted(bodies, key=lambda x: -len(x["body"]))[:5]:
                    ctype = m["headers"].get("content-type", "?")
                    note = m.get("enc_note") or ""
                    head = f"    [{m['status']}] {ctype}  {len(m['body'])} B  ← 流 #{m['flow']}"
                    if note:
                        head += f"  （{note}）"
                    lines.append(head)
                    if not _looks_text(m["body"]):
                        # 二进制正文原样渲染只会灌一屏点号，浪费上下文还遮住重点
                        lines.append("      <不可读字节，已省略渲染；前 16 字节 hex="
                                     + m["body"][:16].hex(" ") + ">")
                        continue
                    preview = _safe_multiline(m["body"][:300], 300)
                    for pl in preview.splitlines()[:8]:
                        lines.append(f"      {pl}")
            if stuck:
                lines.append(f"    ⚠ {len(stuck)} 条正文未还原（"
                             f"{stuck[0].get('enc_note', '')[:70]}）："
                             f"按原文读是乱码，flag 可能正躺在这层压缩里")

        # 指定流全文
        if flow is not None:
            try:
                want = int(str(flow).lstrip("#"))
            except (TypeError, ValueError):
                want = -1
            if 0 <= want < len(flow_ids):
                key = flow_ids[want]
                st = flows[key]
                a, b = st["ends"]
                lines.append("")
                lines.append(f"  === 流 #{want} 全文：{a[0]}:{a[1]} ↔ {b[0]}:{b[1]} ===")
                for end, segs in st["dir"].items():
                    data, gaps, ov = _reassemble(segs)
                    lines.append(f"  -- {end[0]}:{end[1]} 方向（{len(data):,} B，缺口 {len(gaps)} 处，重传 {ov} B）")
                    txt = data[:_PREVIEW].decode("latin-1", errors="replace")
                    txt = "\n".join(l.rstrip() for l in txt.splitlines() if l.strip())
                    lines.append("  " + txt[:_PREVIEW].replace("\n", "\n  "))
                    if len(data) > _PREVIEW:
                        lines.append(f"  …（该方向共 {len(data):,} B，只显示前 {_PREVIEW}）")
            else:
                lines.append("")
                lines.append(f"  flow={flow} 超出范围（0..{len(flow_ids)-1}）")

        # tshark 增强（可选）
        phs, phs_err = _tshark_hierarchy(path)
        if phs:
            keep = [l for l in phs.splitlines() if "frames:" in l or re.search(r"\|\s+\S+ frames:", l)]
            if keep:
                lines.append("")
                lines.append("  协议层次（tshark dissector）")
                for l in keep[:18]:
                    lines.append("    " + l.strip()[:110])
        elif phs_err:
            lines.append("")
            lines.append(f"  （tshark 增强不可用：{phs_err}）")

        # 局限
        limitations = [
            "跨 TCP 段的正文由 seq 重建，非抓包原始顺序；有缺口处用 0x00 填充",
            "TLS/加密正文不可读，只报 SNI 等元数据（无 keylog 无法解密）",
            "HTTP 解析为启发式（覆盖 Content-Length/chunked），畸形报文可能漏切",
        ]
        # 截断必须排在最前面：出口只显示前 3 条，若排在末尾会被自己的显示逻辑
        # 挤掉——最该看到的警告反而看不见（实测踩到）。
        if truncated:
            limitations.insert(0, f"⚠ 只解析了前 {pkt_total:,} 个包（{trunc_reason}），非全集；"
                                  f"建议用 flow/max_packets 参数分段查看")
        if total_held >= _MAX_TOTAL_BYTES:
            limitations.insert(0, "累计流数据达到内存上限，部分流未完整保留")
        if stuck:
            limitations.insert(0, f"⚠ {len(stuck)} 条 HTTP 正文未能还原（"
                                  f"{stuck[0].get('enc_note', '')[:50]}），其中的 flag 不会被扫到")
        status = "partial" if (truncated or reassembled) else "complete"

        lines.append("")
        lines.append("  局限：" + "；".join(limitations[:3]))

        contract = _contract(
            authority="observed",
            status=status,
            truncated=truncated,
            degraded=bool(reassembled) or truncated or bool(stuck),
            reason=("存在 TCP 缺口或重传，或解析被截断" if (reassembled or truncated)
                    else (f"{len(stuck)} 条 HTTP 正文未还原（编码不支持/载荷截断）" if stuck else None)),
            limitations=limitations,
            evidence={
                "tool": "scapy.PcapReader" + ("+tshark" if phs else ""),
                "format": fmt,
                "packets": pkt_total,
                "flows": len(flows),
                "protocols": protos_present[:400],
                "fileSize": size,
                "tsharkAvailable": bool(phs),
                "httpBodies": {
                    "decoded": len([m for m in http_msgs if "已解压" in (m.get("enc_note") or "")]),
                    "undecoded": len(stuck),
                },
            },
        )
        ok = not truncated
        return ToolOutput(text="\n".join(lines), raw=json.dumps(contract, ensure_ascii=False), ok=ok)
