"""misc_traffic_analysis skill：流量包分析流程（pcap 解析/协议识别/数据提取）。

场景：正式赛 misc 可能出流量题（DNS 隧道/HTTP 文件提取/USB 键盘/蓝牙）。
依赖：优先 scapy（若装）；否则用纯 Python 解析 pcap 基本结构。

用法：
    params = {'pcap_path': 'xxx.pcap'}
    result = misc_traffic_analysis(params)
"""

import os
import re
import struct


def _parse_pcap_packets(path: str) -> list:
    """解析 pcap 文件，返回 (timestamp, data) 列表。"""
    packets = []
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return packets
        magic = struct.unpack("<I", header[:4])[0]
        little = magic in (0xA1B2C3D4, 0xA1B23C4D)
        endian = "<" if little else ">"
        if magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = "<" if not little else ">"
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append((ts_sec + ts_usec / 1e6, data))
    return packets


def _parse_pcapng_packets(path: str) -> list:
    """解析 pcapng 文件（SHB 魔数 0x0A0D0D0A），返回 (timestamp, data) 列表。

    pcapng 结构：Section Header Block（魔数 0x0A0D0D0A）+ 若干 Block：
    - Block 通用头：Block Type(4) + Total Length(4) + Body + Pad(4对齐) + Total Length(4)
    - Type 1 = IDB（接口描述，跳过）；Type 3 = SPB（简单包）；Type 6 = EPB（增强包，含时间戳）
    """
    packets = []
    with open(path, "rb") as f:
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            btype, total_len = struct.unpack("<II", hdr)
            if total_len < 12:
                break
            body = f.read(total_len - 8)
            if len(body) < total_len - 8:
                break
            if btype == 6:  # EPB: iface(4)+ts_hi(4)+ts_lo(4)+caplen(4)+origlen(4)+data
                if len(body) >= 20:
                    _iface, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack("<IIIII", body[:20])
                    pkt = body[20:20 + cap_len]
                    ts = (ts_hi << 32 | ts_lo) / 1_000_000  # 微秒
                    packets.append((ts, pkt))
            elif btype == 3:  # SPB: origlen(4) + data
                if len(body) >= 4:
                    orig_len = struct.unpack("<I", body[:4])[0]
                    pkt = body[4:4 + orig_len]
                    packets.append((0.0, pkt))
            # 跳到下一块（Total Length 重复在尾部，body 已含全部，继续读下一块）
    return packets


def _extract_ascii(data: bytes, min_len: int = 6) -> list:
    """提取 ASCII 字符串（flag 常以可读字符串出现在载荷）。"""
    return [s.decode("utf-8", errors="replace")
            for s in re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def _detect_kind(packets: list) -> dict:
    """粗略识别流量类型。"""
    all_data = b"".join(d for _, d in packets)
    kind_hits = []
    if b"DNS" in all_data or b"\x00\x01\x00\x00\x00\x01\x00\x00" in all_data[:2000]:
        kind_hits.append("dns")
    if b"GET " in all_data or b"HTTP" in all_data or b"POST " in all_data:
        kind_hits.append("http")
    if b"\x13\x00\x13" in all_data or b"HID" in all_data:
        kind_hits.append("usb_keyboard")
    if b"BD_ADDR" in all_data or b"L2CAP" in all_data:
        kind_hits.append("bluetooth")
    if b"\x08\x00\x45\x00" in all_data:  # IPv4
        kind_hits.append("ip")
    return {"detected": kind_hits, "packet_count": len(packets), "total_bytes": len(all_data)}


def _extract_flags_from_text(texts: list) -> list:
    flags = []
    for t in texts:
        for m in re.finditer(r"(?:DASCTF|flag|ctf)\{[^}\s]{4,}\}", t, re.I):
            flags.append(m.group(0))
    return flags


def misc_traffic_analysis(params: dict) -> dict:
    """skill 入口：解析 pcap，识别类型，提取 flag。"""
    path = params.get("pcap_path", "")
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "pcap_path 不存在"}

    # 按魔数自动选择解析器：pcapng（0x0A0D0D0A）vs 经典 pcap（0xA1B2C3D4）
    with open(path, "rb") as _f:
        magic = _f.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        packets = _parse_pcapng_packets(path)
    else:
        packets = _parse_pcap_packets(path)
    if not packets:
        return {"ok": False, "error": "pcap 解析失败（空或格式不支持）"}

    info = _detect_kind(packets)
    # 提取所有 ASCII 字符串
    texts = []
    for _, data in packets:
        texts.extend(_extract_ascii(data))
    flags = _extract_flags_from_text(texts)

    result = {
        "ok": True,
        "packets": len(packets),
        "detected_kinds": info["detected"],
        "ascii_samples": texts[:20],
        "flags": flags,
    }
    # DNS 隧道：子域名标签拼接（如 MR/XH/... 拼 base32）
    if "dns" in info["detected"]:
        labels = re.findall(rb"([A-Z2-7]{2,})\.", b"\n".join(d for _, d in packets))
        if labels:
            import base64

            joined = b"".join(labels)
            try:
                pad = b"=" * ((8 - len(joined) % 8) % 8)
                decoded = base64.b32decode(joined + pad)
                result["dns_tunnel_decoded"] = decoded.decode("utf-8", errors="replace")
            except Exception:
                pass
    return result


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return misc_traffic_analysis(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="misc 流量分析")
    parser.add_argument("--pcap", required=True, help="pcap 路径")
    args = parser.parse_args()
    import json

    print(json.dumps(misc_traffic_analysis({"pcap_path": args.pcap}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()


def suggest_steps(description=None, attachments=None):
    """解题步骤建议（misc-007/009 空转教训：必须带附件路径起步）。"""
    return [
        "第一步：file_analyze(附件路径) —— 路径必须从题目 attachments 字段取，禁止不传路径空转（会被监督判幻觉）",
        "识别流量类型：DNS 隧道/HTTP 文件传输/USB 键盘/蓝牙 → 选对应提取策略",
        "提取隐藏数据 → base64/hex 解码 → 拼装 flag",
    ]
