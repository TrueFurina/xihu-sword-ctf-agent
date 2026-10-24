"""pcap_probe 回归测试。

重点不是「能跑通」，而是锁住三个最容易静默出错的点：
  1. TCP 重组必须按 seq 排序（乱序到达是常态）
  2. 重传必须去重（同 seq 同内容不能拼两遍）
  3. flag 跨段时必须能拼回来（单看任何一段都没有完整 flag）

第 3 条是整条链的价值所在：不重组就必然漏 flag，而且**不会报错**——
只是结果里没有而已。这种「静默漏掉」比崩溃危险得多，必须有测试守着。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.adapters import pcap_probe as pp  # noqa: E402


# ── 纯函数层：重组语义 ────────────────────────────────

def test_reassemble_joins_in_seq_order():
    """乱序到达的段必须按 seq 拼成正确顺序。"""
    segs = [(106, b"world"), (100, b"hello ")]
    data, gaps, ov = pp._reassemble(segs)
    assert data == b"hello world"
    assert gaps == []
    assert ov == 0


def test_reassemble_dedups_retransmission():
    """同 seq 同内容出现两次（重传），只能保留一份。"""
    segs = [(100, b"abcdef"), (100, b"abcdef"), (106, b"ghi")]
    data, gaps, ov = pp._reassemble(segs)
    assert data == b"abcdefghi"
    assert ov == 6, "重传的 6 字节应计入 overlap，而不是拼进正文"


def test_reassemble_records_gap():
    """缺包要留下缺口记录，并用 0x00 占位保持后续偏移可算。"""
    segs = [(100, b"abc"), (110, b"xyz")]
    data, gaps, ov = pp._reassemble(segs)
    assert data == b"abc" + b"\x00" * 7 + b"xyz"
    assert gaps == [(3, 7)]


def test_reassemble_flag_split_across_segments():
    """flag 被切在两段之间，且两段**乱序到达**——CTF 里最常见的埋法。

    故意把 sec 段放在前面：如果重组器不按 seq 排序，这条会直接失败。
    """
    half1, half2 = b"the answer is flag{cross_", b"segment_flag}\n"
    segs = [(200 + len(half1), half2), (200, half1)]     # 乱序
    data, _, _ = pp._reassemble(segs)
    assert data == half1 + half2, "乱序段必须按 seq 排回原序"
    hits = pp._flags_in([data.decode("latin-1")])
    assert "flag{cross_segment_flag}" in hits
    # 且单独看任一段都拿不到
    assert pp._flags_in([half1.decode("latin-1")]) == []
    assert pp._flags_in([half2.decode("latin-1")]) == []


def test_reassemble_partial_overlap_keeps_first():
    """部分重叠时保留先到内容，跳过被覆盖部分（真实 TCP 语义）。"""
    segs = [(100, b"abcdef"), (103, b"defghi")]
    data, gaps, ov = pp._reassemble(segs)
    assert data == b"abcdefghi"
    assert ov == 3


# ── HTTP / TLS 解析 ───────────────────────────────────

def test_split_http_request_and_response():
    req = (b"POST /login HTTP/1.1\r\nHost: a.local\r\n"
           b"Content-Length: 11\r\n\r\nuser=admin1")
    msgs = pp._split_http(req)
    assert len(msgs) == 1
    assert msgs[0]["kind"] == "req"
    assert msgs[0]["method"] == "POST"
    assert msgs[0]["target"] == "/login"
    assert b"user=admin" in msgs[0]["body"]

    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    msgs = pp._split_http(resp)
    assert msgs[0]["kind"] == "resp"
    assert msgs[0]["status"] == 200
    assert msgs[0]["body"] == b"hello"


def test_split_http_chunked():
    """chunked 正文必须解开，否则 flag 会被 chunk 长度前缀切断。"""
    body = b"flag{chunked_body_ok}"
    chunked = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
               + format(len(body), "x").encode() + b"\r\n" + body + b"\r\n0\r\n\r\n")
    msgs = pp._split_http(chunked)
    assert msgs[0]["body"] == body


def test_sni_extracted_from_client_hello():
    """SNI 必须靠 name_len 交叉校验，random 里的裸 00 00 不能误判。"""
    payload = (b"\x16\x03\x01\x00\x4f"          # TLS record
               b"\x01\x00\x00\x4b\x03\x03"      # handshake + version
               + b"\x11" * 32                   # random（故意全 0x11）
               + b"\x00" + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00"
               + b"\x00\x1e"                    # extensions len
               + b"\x00\x00\x00\x1a\x00\x18\x00\x00\x15" + b"admin.challenge.local")
    assert pp._sni_of(payload) == "admin.challenge.local"


def test_sni_returns_none_on_garbage():
    assert pp._sni_of(b"") is None
    assert pp._sni_of(b"\x16\x03\x01" + b"\x00" * 40) is None
    assert pp._sni_of(b"not tls at all") is None


def test_magic_detection():
    assert pp._looks_like_pcap(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20) == "pcap/LE"
    assert pp._looks_like_pcap(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20) == "pcapng"
    assert pp._looks_like_pcap(b"PK\x03\x04" + b"\x00" * 20) is None


# ── 端到端（真 pcap，scapy 现场生成）──────────────────

def _build_pcap(path: str) -> str:
    """造一份最小但含全部陷阱的 pcap：跨段 flag + 乱序 + 重传 + DNS + SNI。"""
    from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, wrpcap

    flag = "flag{e2e_cross_segment_ok}"
    body = ("head-" + flag + "-tail").encode()
    cut = body.index(b"flag{") + 5          # 切在 flag 中间
    p1, p2 = body[:cut], body[cut:]
    seq = 5000

    pkts = [
        IP(src="10.9.9.5", dst="10.9.9.9") / TCP(sport=33333, dport=80, flags="S", seq=seq),
        IP(src="10.9.9.9", dst="10.9.9.5") / TCP(sport=80, dport=33333, flags="SA", seq=seq, ack=seq + 1),
        # 请求
        IP(src="10.9.9.5", dst="10.9.9.9") / TCP(sport=33333, dport=80, flags="PA", seq=seq + 1) /
        Raw(load=b"GET /s.txt HTTP/1.1\r\nHost: e2e.local\r\n\r\n"),
    ]
    hdr = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    rseq = seq
    # 故意乱序写入：先第二段，再响应头，再第一段；且第一段重复一次（重传）
    pkts += [
        IP(src="10.9.9.9", dst="10.9.9.5") / TCP(sport=80, dport=33333, flags="PA",
                                                 seq=rseq + len(hdr) + len(p1)) / Raw(load=p2),
        IP(src="10.9.9.9", dst="10.9.9.5") / TCP(sport=80, dport=33333, flags="PA",
                                                 seq=rseq) / Raw(load=hdr),
        IP(src="10.9.9.9", dst="10.9.9.5") / TCP(sport=80, dport=33333, flags="PA",
                                                 seq=rseq + len(hdr)) / Raw(load=p1),
        IP(src="10.9.9.9", dst="10.9.9.5") / TCP(sport=80, dport=33333, flags="PA",
                                                 seq=rseq + len(hdr)) / Raw(load=p1),   # 重传
        # DNS
        IP(src="10.9.9.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) /
        DNS(id=1, rd=1, qd=DNSQR(qname="e2e.local")),
        # TLS SNI（"sni.e2e.local" 是 13 字节，name_len 必须写 0x0d）
        IP(src="10.9.9.5", dst="1.1.1.1") / TCP(sport=44444, dport=443, flags="PA", seq=1) /
        Raw(load=(b"\x16\x03\x01\x00\x4a\x01\x00\x00\x46\x03\x03" + b"\x22" * 32 +
                  b"\x00\x00\x04\x13\x01\x13\x02\x01\x00\x00\x1e"
                  b"\x00\x00\x00\x1a\x00\x18\x00\x00\x0d" + b"sni.e2e.local")),
    ]
    wrpcap(path, pkts)
    return flag


@pytest.mark.asyncio
async def test_end_to_end(tmp_path):
    p = str(tmp_path / "e2e.pcap")
    flag = _build_pcap(p)
    out = await pp.PcapProbeAdapter().run({"path": p})

    assert out.ok
    assert flag in out.text, "跨段+乱序+重传三重条件下 flag 必须被重组出来"
    assert "e2e.local" in out.text
    assert "sni.e2e.local" in out.text
    assert "重传" in out.text, "重传字节数应被标注"


@pytest.mark.asyncio
async def test_non_pcap_is_not_applicable(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    out = await pp.PcapProbeAdapter().run({"path": str(p)})
    assert not out.ok
    assert "不是 pcap" in out.text


@pytest.mark.asyncio
async def test_empty_pcap_does_not_crash(tmp_path):
    from scapy.all import wrpcap
    p = str(tmp_path / "empty.pcap")
    wrpcap(p, [])
    out = await pp.PcapProbeAdapter().run({"path": p})
    assert "包 0" in out.text


def test_split_http_gzip_body_is_decompressed():
    """Content-Encoding: gzip 的正文必须解压。

    2026-10-20 由真实抓包（Wireshark 官方 http.cap）触发：一个标着 text/html 的
    1272 B 响应实际是 gzip 压缩（解压后 3608 B），原样打印是一屏乱码。
    合成样本里我写的都是明文正文，所以此前从未测到——flag 藏在这种正文里就永远看不见。
    """
    import gzip

    body = b"<html><body>flag{gzip_hidden}</body></html>"
    comp = gzip.compress(body)
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n"
            + b"Content-Length: " + str(len(comp)).encode() + b"\r\n\r\n" + comp)

    msgs = pp._split_http(resp)

    assert msgs[0]["body"] == body, "正文没解压 → gzip 里的 flag 永远扫不到"
    assert "已解压" in msgs[0]["enc_note"]
    assert pp._flags_in([msgs[0]["body"].decode("latin-1")]) == ["flag{gzip_hidden}"]


def test_split_http_deflate_body_is_decompressed():
    import zlib

    body = b"deflate body flag{deflate_ok}"
    comp = zlib.compress(body)
    resp = (b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n"
            + b"Content-Length: " + str(len(comp)).encode() + b"\r\n\r\n" + comp)

    assert pp._split_http(resp)[0]["body"] == body


def test_undecodable_binary_body_is_not_rendered_as_dots():
    assert pp._looks_text(bytes(range(256)) * 4) is False
    assert pp._looks_text(b"plain ascii flag{x}") is True
    assert pp._looks_text(b"") is True


# ── Content-Encoding 覆盖：br / zstd / 多段 / 未知 / 截断 ────────────────
# 2026-10-20 二轮。旧实现只认 gzip/deflate，`br` 既不命中关键词、也没有魔数，
# 正文被当成明文塞进上下文：读起来是乱码，却没有任何「这是压缩态」的标记。
# 这一组测试锁的就是「不许静默」。


def _resp(enc: str, body: bytes, ctype: str = "text/html") -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype.encode()
            + b"\r\nContent-Encoding: " + enc.encode()
            + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def test_split_http_brotli_body_is_decompressed():
    brotli = pytest.importorskip("brotli")
    body = b"<html><body>flag{br0tli_in_traffic}</body></html>"
    msgs = pp._split_http(_resp("br", brotli.compress(body)))

    assert msgs[0]["body"] == body, "br 正文没解压 → 现代站点上的 flag 必然漏"
    assert msgs[0]["enc_note"].startswith("br 已解压")
    assert pp._flags_in([msgs[0]["body"].decode("latin-1")]) == ["flag{br0tli_in_traffic}"]


def test_split_http_zstd_body_is_decompressed():
    zstd = pytest.importorskip("zstandard")
    body = b"zstd body flag{zstd_in_traffic}"
    msgs = pp._split_http(_resp("zstd", zstd.ZstdCompressor().compress(body)))

    assert msgs[0]["body"] == body
    assert msgs[0]["enc_note"].startswith("zstd 已解压")


def test_split_http_multi_encoding_decodes_in_reverse():
    """`Content-Encoding: gzip, br` = 先 gzip 再 br，解码必须逆序。"""
    brotli = pytest.importorskip("brotli")
    import gzip

    body = b"double encoded flag{two_layers}"
    comp = brotli.compress(gzip.compress(body))
    msgs = pp._split_http(_resp("gzip, br", comp))

    assert msgs[0]["body"] == body
    assert "gzip 已解压" in msgs[0]["enc_note"] and "br 已解压" in msgs[0]["enc_note"]


def test_unknown_content_encoding_is_reported_not_silent():
    """不认识的编码必须留痕；静默当明文是最坏的降级方式。"""
    raw = b"\x00\x01\x02flag{stuck_in_unknown_codec}"
    msgs = pp._split_http(_resp("x-custom", raw))

    assert msgs[0]["body"] == raw
    assert msgs[0]["enc_note"].startswith("未支持编码 x-custom")
    assert "压缩态" in msgs[0]["enc_note"]


def test_truncated_brotli_is_marked_incomplete():
    """截断的 br 会安静吐出半截正文（实测无异常），绝不能报「已解压」。"""
    brotli = pytest.importorskip("brotli")
    full = brotli.compress(b"flag{truncated_body_should_not_claim_success}" * 4)
    body, note = pp._inflate(full[:-3], "br")

    assert not note.startswith("br 已解压"), f"截断却报成功：{note}"
    assert note.startswith("解压不完整"), note
    assert note.startswith(pp._STUCK_PREFIX)


def test_truncated_zstd_is_reconciled_against_declared_size():
    """zstd 帧头声明了原始长度，截断时用它对账（stream_reader 不一定抛异常）。"""
    zstd = pytest.importorskip("zstandard")
    plain = b"flag{zstd_declared_size}"
    raw = zstd.ZstdCompressor().compress(plain)
    body, note = pp._inflate(raw[:-4], "zstd")

    assert len(body) < len(plain)
    assert note.startswith("解压不完整") and "声明" in note


def test_brotli_output_is_capped(monkeypatch):
    """压缩炸弹：1 KB 上限下不得解出 100 KB。"""
    brotli = pytest.importorskip("brotli")
    monkeypatch.setattr(pp, "_MAX_INFLATE", 1024)
    out, note = pp._inflate(brotli.compress(b"A" * 100_000), "br")

    assert len(out) == 1024, f"上限失效，解出 {len(out)} B"
    assert "截断" in note


def _build_http_pcap(path: str, resp_head: bytes, body: bytes) -> None:
    """造一份响应正文分两段的 pcap（切在压缩正文中间，真实抓包常态）。"""
    from scapy.all import IP, TCP, Raw, wrpcap

    seq = 1000
    pkts = [
        IP(src="10.1.1.5", dst="10.1.1.9") / TCP(sport=40000, dport=80, flags="S", seq=seq),
        IP(src="10.1.1.9", dst="10.1.1.5") / TCP(sport=80, dport=40000, flags="SA",
                                              seq=seq, ack=seq + 1),
        IP(src="10.1.1.5", dst="10.1.1.9") / TCP(sport=40000, dport=80, flags="PA",
                                                 seq=seq + 1) /
        Raw(load=b"GET /index.html HTTP/1.1\r\nHost: br.local\r\n\r\n"),
        IP(src="10.1.1.9", dst="10.1.1.5") / TCP(sport=80, dport=40000, flags="PA",
                                                 seq=seq) / Raw(load=resp_head),
        IP(src="10.1.1.9", dst="10.1.1.5") / TCP(sport=80, dport=40000, flags="PA",
                                                 seq=seq + len(resp_head)) / Raw(load=body),
    ]
    wrpcap(path, pkts)


@pytest.mark.asyncio
async def test_brotli_body_end_to_end_through_adapter(tmp_path):
    """全链路：pcap → 流重组 → HTTP 切分 → br 解压 → flag 进上下文。"""
    import json

    brotli = pytest.importorskip("brotli")
    flag = "flag{br_e2e_recovered}"
    comp = brotli.compress(f"<html><body>{flag}</body></html>".encode())
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n"
            b"Content-Length: " + str(len(comp)).encode() + b"\r\n\r\n")
    p = str(tmp_path / "br.pcap")
    _build_http_pcap(p, head, comp)

    out = await pp.PcapProbeAdapter().run({"path": p})
    contract = json.loads(out.raw)

    assert flag in out.text, "解压后的正文没有进上下文"
    assert contract["evidence"]["httpBodies"]["decoded"] >= 1
    assert contract["evidence"]["httpBodies"]["undecoded"] == 0
    assert contract["degraded"] is False


@pytest.mark.asyncio
async def test_unknown_encoding_end_to_end_degrades(tmp_path):
    """解不开的正文必须把整份结论标成 degraded，并写进 limitations。"""
    import json

    raw = b"\x00\x01flag{never_decoded}"
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Encoding: x-custom\r\n"
            b"Content-Length: " + str(len(raw)).encode() + b"\r\n\r\n")
    p = str(tmp_path / "cx.pcap")
    _build_http_pcap(p, head, raw)

    out = await pp.PcapProbeAdapter().run({"path": p})
    contract = json.loads(out.raw)

    assert contract["degraded"] is True
    assert any("未能还原" in l for l in contract["limitations"]), contract["limitations"]
    assert "未还原" in out.text


@pytest.mark.asyncio
async def test_flag_beyond_preview_in_compressed_body_still_listed(tmp_path):
    """压缩正文里的 flag，即使超出 300 B 预览窗口，也必须进「★ flag 候选」。

    这是召回的真问题：流级裸扫看的是压缩态字节，一个字符都匹配不到；正文预览
    只渲染前 300 B。两者之间就是盲区 —— flag 放在正文第 1 KB 处就会彻底消失。
    """
    brotli = pytest.importorskip("brotli")
    flag = "flag{beyond_the_preview_window}"
    body = b"<html><body>" + b"x" * 1200 + flag.encode() + b"</body></html>"
    comp = brotli.compress(body)
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n"
            b"Content-Length: " + str(len(comp)).encode() + b"\r\n\r\n")
    p = str(tmp_path / "deep.pcap")
    _build_http_pcap(p, head, comp)

    out = await pp.PcapProbeAdapter().run({"path": p})
    cand_lines = [l for l in out.text.splitlines()
                  if flag in l and ("←" in l)]

    assert cand_lines, "压缩正文深处的 flag 没进候选列表"
    assert "解压后正文" in cand_lines[0]
