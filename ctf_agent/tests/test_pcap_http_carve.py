"""skills/pcap_http_carve（pcap → HTTP 表单 hex 片段 → 拼接还原嵌入文件）行为 + 变异测试。

真实性：真实 CSAW-Quals 2017 forensics「missed_registration」的 sha256 锁——附件或
       tesseract 缺失时跳过；断言返回值 sha256 与题面 flag_sha256 逐字一致（不落明文 flag）。
合成：自建最小合法 pcap（Ethernet+IPv4+TCP），把一个 BMP 切成多段 hex、分散进多个
       POST 表单的额外字段，断言 carve 能逐字节还原。
变异验证：关掉魔数判定 / hex 片段提取，合成与真题必须**还原不出**——证明「是这些判据在解」。
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import pcap_http_carve as P  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_ATT = _ROOT / "data" / "questions_ext" / "_attachments" / "forensics"
_POOL_DIR = _ROOT / "data" / "questions_ext"
_REAL_PCAP = _ATT / "2017q-for-missed_registration" / "cap.pcap"
_REAL_QID = "ext_nyu_ctf_bench_2017q_for_missed_registration"
_REAL_SHA = "b0e408d1da7e9310fd1c9818c0690a3df85fe52bf609912e4688407432a5b22e"
# sha256 以题面 JSON 为唯一真值源（避免手抄漂移）
_j = _POOL_DIR / "forensics" / f"{_REAL_QID}.json"
if _j.exists():
    import json as _json
    _REAL_SHA = _json.loads(_j.read_text(encoding="utf-8"))["flag_sha256"]

try:
    from skills.svg_path_text import _find_tesseract
    _HAS_TESS = _find_tesseract() is not None
except Exception:  # noqa: BLE001
    _HAS_TESS = False

_need_pcap = pytest.mark.skipif(not _REAL_PCAP.exists(), reason=f"真题附件缺失: {_REAL_PCAP}")
_need_ocr = pytest.mark.skipif(not _HAS_TESS, reason="系统无 tesseract")


# ------------------------------------------------------------------ 合成工具
def _ip2b(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _frame(payload: bytes, sport=12345, dport=8080,
           src="192.168.0.10", dst="192.168.0.21") -> bytes:
    """构造一个最小 Ethernet+IPv4+TCP 帧（不做校验和，解析器不校验）。"""
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x18, 0xFFFF, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     _ip2b(src), _ip2b(dst))
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + ip + tcp


def _pcap(frames) -> bytes:
    """frames: iterable[bytes] → 经典 libpcap（LE, linktype=1）。"""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for i, fr in enumerate(frames):
        out += struct.pack("<IIII", 1600000000 + i, 0, len(fr), len(fr)) + fr
    return out


def _post_body(fields) -> bytes:
    q = "&".join(f"{k}={v}" for k, v in fields)
    return ("POST / HTTP/1.1\r\nHost: 192.168.0.21:8080\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\n" + q).encode("latin-1")


def _frame_seq(bodies):
    """每条请求用**不同源端口**（否则会被折叠成同一条 TCP 流），构造 pcap 帧序列。"""
    return [_frame(b, sport=40000 + i) for i, b in enumerate(bodies)]


def _tiny_bmp(w=4, h=4) -> bytes:
    """构造一个 4x4 24bpp BMP（行已 4 字节对齐）。"""
    row = w * 3
    if row % 4:
        row += 4 - row % 4
    imgsize = row * h
    off = 54
    filesize = off + imgsize
    hdr = b"BM" + struct.pack("<IHHI", filesize, 0, 0, off)
    dib = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, imgsize, 2835, 2835, 0, 0)
    px = bytes((i * 7) & 0xFF for i in range(imgsize))
    return hdr + dib + px


def _pad_chunks(data: bytes, size: int = 12):
    """把 data 补齐到 size 的整数倍后按 size 切块——保证每块 hex 长度 ≥ _MIN_HEX_LEN。"""
    if len(data) % size:
        data = data + b"\x00" * (size - len(data) % size)
    return [data[i:i + size] for i in range(0, len(data), size)]


# ------------------------------------------------------------------ 解析单测
def test_is_pcap():
    assert P._is_pcap(_pcap([]))
    assert not P._is_pcap(b"not a pcap at all........")
    assert not P._is_pcap(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)


def test_tcp_payload_ethernet():
    fr = _frame(b"POST / HTTP/1.1\r\n\r\n")
    info = P._tcp_payload(fr, 1)
    assert info is not None
    src, sport, dst, dport, pl = info
    assert (src, dport) == ("192.168.0.10", 8080)
    assert pl.startswith(b"POST /")


def test_tcp_payload_rejects_non_ip():
    fr = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 40   # ARP ethertype
    assert P._tcp_payload(fr, 1) is None


def test_split_http_tolerates_leading_nul():
    buf = b"\x00\x00\x00\x00POST / HTTP/1.1\r\n\r\nbody"
    parts = P._split_http(buf)
    assert parts is not None and parts[1] == b"body"
    assert P._split_http(b"garbage\x00\x00") is None


def test_parse_form_and_hex_fragment():
    longhex = "424d9235" * 3           # 24 hex chars ≥ _MIN_HEX_LEN
    form = P._parse_form(("name=Amy&x=" + longhex + "\x00\x00\x00&n=abc").encode("latin-1"))
    assert form["name"] == "Amy"
    assert P._hex_fragment(form["x"]) == bytes.fromhex(longhex)
    # 奇数长 / 太短 → None
    assert P._hex_fragment("abc") is None
    assert P._hex_fragment("424d9") is None
    assert P._hex_fragment("424d9235") is None     # 8 hex < 20


def test_detect_kind_and_declared_size():
    bmp = _tiny_bmp()
    assert P._detect_kind(bmp) == "bmp"
    assert P._declared_size(bmp, "bmp") == len(bmp)
    assert P._detect_kind(b"PK\x03\x04xxxx") == "zip"
    assert P._detect_kind(b"nope") is None


# ------------------------------------------------------------------ carve 往返
def test_carve_roundtrip_split_fragments():
    bmp = _tiny_bmp()
    frags = _pad_chunks(bmp, 12)
    assert all(len(f) >= P._MIN_HEX_LEN // 2 for f in frags)
    bodies = [_post_body([("name", "Amy"), ("x", frag.hex())]) for frag in frags]
    got = P.carve(_pcap(_frame_seq(bodies)))
    assert got == bmp


def test_carve_ignores_short_hex_and_other_fields():
    # 只有普通字段（无长 hex）→ 无法还原
    bodies = [_post_body([("name", "Amy"), ("n", "abcdef")]) for _ in range(3)]
    assert P.carve(_pcap(_frame_seq(bodies))) is None


def test_carve_rejects_non_pcap():
    assert P.carve(b"\x00" * 64) is None
    assert P.carve(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64) is None


def test_carve_trims_to_declared_bmp_size():
    bmp = _tiny_bmp()
    # 追加噪声字节：carve 必须按 BMP 头里的 filesize 裁回正确长度
    payload = bmp + b"\xde\xad\xbe\xef"
    bodies = [_post_body([("x", f.hex())]) for f in _pad_chunks(payload, 12)]
    assert P.carve(_pcap(_frame_seq(bodies))) == bmp


# ------------------------------------------------------------------ run 接口
def test_run_carve_only_returns_file():
    bmp = _tiny_bmp()
    frames = [_frame(_post_body([("x", bmp.hex())]))]
    assert P.run({"raw": _pcap(frames), "carve_only": True}) == bmp


def test_run_negative_cases():
    assert P.run({"raw": b"not a pcap"}) is None
    assert P.run({"path": str(_ROOT / "does_not_exist.pcap")}) is None
    assert P.run("not a dict") is None  # type: ignore[arg-type]
    # 合法 pcap 但无可还原文件
    assert P.run({"raw": _pcap([_frame(_post_body([("a", "b")]))])}) is None


def test_run_prefers_flag_when_carved_is_text():
    # 非图片：carve 出的文件里直接含 flag 形态 → 直接返回（zip 魔数保证能被 carve 认出）
    blob = b"PK\x03\x04" + b"...FLAG{synthetic_carve_ok}...tail"
    frames = [_frame(_post_body([("x", blob.hex())]))]
    got = P.run({"raw": _pcap(frames)})
    assert got == b"FLAG{synthetic_carve_ok}"


# ------------------------------------------------------------------ 真题 sha256 锁
@_need_pcap
@_need_ocr
def test_real_challenge_sha256_lock():
    s = P.solve(str(_REAL_PCAP))
    assert s is not None, "真题未解出"
    assert hashlib.sha256(s.encode()).hexdigest() == _REAL_SHA


@_need_pcap
def test_real_challenge_carve_size():
    carved = P.carve(_REAL_PCAP.read_bytes())
    assert carved is not None and carved[:2] == b"BM"
    assert len(carved) == struct.unpack_from("<I", carved, 2)[0]


# ------------------------------------------------------------------ 接线
def test_presolve_wiring():
    from core import presolve as ps
    mods = ps.wired_skill_modules()
    assert "skills.pcap_http_carve" in mods
    assert hasattr(ps, "_try_pcap_http_carve")


@_need_pcap
@_need_ocr
def test_presolve_end_to_end():
    import asyncio
    from eval.cases import load_questions
    from core import presolve as ps
    qs = load_questions(str(_POOL_DIR), include_disclosed=True)
    q = next((x for x in qs if x.id == _REAL_QID), None)
    assert q is not None
    assert asyncio.run(ps.presolve(q, force=True)) is not None


# ------------------------------------------------------------------ 变异验证
def test_mutation_break_magic_detection(monkeypatch):
    bmp = _tiny_bmp()
    frames = [_frame(_post_body([("x", bmp.hex())]))]
    pcap = _pcap(frames)
    assert P.carve(pcap) == bmp                       # 基线
    monkeypatch.setattr(P, "_detect_kind", lambda data: None)
    assert P.carve(pcap) is None                      # 关魔数判定 → 还原不出


def test_mutation_break_hex_extraction(monkeypatch):
    bmp = _tiny_bmp()
    frames = [_frame(_post_body([("x", bmp.hex())]))]
    pcap = _pcap(frames)
    assert P.carve(pcap) == bmp
    monkeypatch.setattr(P, "_hex_fragment", lambda v: None)
    assert P.carve(pcap) is None                      # 关片段提取 → 还原不出
