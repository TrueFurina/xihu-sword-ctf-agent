#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""10735 MISC-02 "logbool" — SQL 布尔盲注流量重放，可复现离线核验脚本。

真题来源：data/race_details/10735.json + 附件
          data/race_attachments/10735_logbool的附件/tempdir/MISC附件/logbool.pcapng
（16MB / 110701 包；附件本地保留，.gitignore data/race_attachments/ 排除不入 HEAD；
本 verifier 通过本地附件存在性 + 攻击链完整执行做闭环）

攻击链（2026-09-03 从 pcap 全链重建固化；2026-08-24 本机原版手动跑通 + 归档
_archive/ctf_agent_broken/ 保留中间产物，2026-08-27 因"附件全仓缺失/脚本散落"
诚实校准移出 KPI）：
  1) scapy 读 pcap → 按 TCP 连接重装 HTTP 流 → 顺序解析出 (GET /?id=, 响应体) 对
  2) 全部请求均为 sqlmap 布尔盲注谓词：
       ORD(MID((SELECT IFNULL(CAST(<col> AS NCHAR),0x20) FROM ctftest.ctfblob
                ORDER BY id LIMIT <row>,1),<pos>,1))><thr>
     （COUNT(*) 探针无 LIMIT；响应体以 </br></br>success 结尾 = 谓词为真）
  3) 逐 (列,行,位) 收集 (thr, is_true) 对 → 鲁棒解码（0..255 上 argmin 冲突数）
     ——个别 probe 谎报 true 亦不影响结果
  4) content 列还原 338-hex（= 带密码 RAR5 的 hex），password 列 = RAR 密码
  5) 7z.exe（完整版，支持 RAR5）带密码解压 → flag.txt
  6) 输出 REGRESS_PASS + 各步 sha256 摘要（flag 字符串不落 verifier 输出 / 不入 git）

honest 边界（与 10732 同款治理口径，2026-09-03）：
  - 三重 sha256 锚均命中：content-hex sha256=380c0718…（RAR hex）、rar 字节
    sha256=a7699a1d…（与归档 logbool.rar 逐字节一致）、flag.txt sha256=67f3e126…
    （与台账 2026-08-24 记录前缀 67f3e126d51a6169 及归档 _10735_unrar/flag.txt
    逐字节一致——2026-08-24 与 2026-09-03 两次独立运行交叉互证）
  - 但题面 data/race_details/10735.json **无 flag_sha256 字段**（DASCTF 平台题，
    description 仅 "MISC-02"，flag 字段为空待解），无可自动化校验的外部真值库；
    sha 锚点均源自 2026-08-24 自记录/归档中间产物（logbool.rar / flag.txt），
    属「自证双运行一致」而非外部官方真值——若写 PROMOTION_EVIDENCE 属自我授权
    （pcap 重放 → 自己算 sha256 → 自己写白名单，闭环自洽但无外部校验）。
  - 因此 10735 治理归位 = 可机器复现 verifier 落库 + REGRESSION_CHECKS 入条目 +
    KNOWN_GAP 移除；**不进 PROMOTION_EVIDENCE = 不升 KPI 水位**（KPI_WATERMARK 12
    不动、台账 ✅ offline_verified 不增，防 WATERMARK_DRIFT）——与 10732 治理
    修复、与 9→10/10→11/11→12 三道带证晋级模式不同的第三类：既不是带外部真值
    晋级，也不是留在 KNOWN_GAP，而是「可复现闭环 + 诚信不入严格 KPI」。

运行：.venv/Scripts/python.exe scripts/verify_10735.py
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import zlib
from collections import defaultdict

from scapy.all import Raw, TCP, rdpcap  # .venv 已装 scapy 2.7.0


PCAP = os.path.join(
    "data", "race_attachments",
    "10735_logbool的附件", "tempdir", "MISC附件", "logbool.pcapng",
)
SEVEN_ZIP = os.path.join("data", "race_attachments", "_bin", "7z.exe")

# 结果写到 results 隔离区（gitignore 排除不入 HEAD）
RESULTS_DIR = os.path.join("data", "results", "_verify_10735")
RAR_OUT = os.path.join(RESULTS_DIR, "_replay_logbool.rar")

# 三重 sha256 锚（2026-08-24 自记录/归档交叉；非题面官方——见 docstring honest 边界）
CONTENT_HEX_SHA256 = "380c0718aa5772849557787c8c7cbe7b7d7415dac12c8d1e2cb5341349c5c0de"
RAR_SHA256 = "a7699a1dbd4dd1826a783b8447b3c97085aed67c0e28b6252fbbb05e730b0d3c"
FLAG_SHA256 = "67f3e126d51a61698b45a40d0cd82e75d544b208c2bdfc8301927f55fc19924f"
FLAG_LEN = 40  # DASCTF{<32hex>}

_PRED_PAT = re.compile(
    r"ORD\(MID\(\(SELECT (.*?) FROM ctftest\.ctfblob"
    r"(?: ORDER BY id LIMIT (\d+),1)?\),(\d+),1\)\)>(\d+)"
)
_TRUE_MARK = b"</br></br>success"


def _field_of(expr: str) -> str:
    m = re.search(r"CAST\((\w+) AS NCHAR\)", expr)
    if m:
        return m.group(1)
    if "COUNT(*)" in expr:
        return "count"
    return expr[:40]


def _load_pairs(pcap: str):
    """读 pcap → 按 TCP 连接重装 HTTP 流 → 顺序解析 (unquoted_url, body) 对。"""
    pkts = rdpcap(pcap)
    conns = defaultdict(lambda: {"c": [], "s": []})
    for p in pkts:
        if p.haslayer(Raw) and p.haslayer(TCP):
            t = p[TCP]
            if t.dport == 80:
                conns[t.sport]["c"].append((t.seq, bytes(p[Raw].load)))
            elif t.sport == 80:
                conns[t.dport]["s"].append((t.seq, bytes(p[Raw].load)))

    def asm(chunks):
        chunks.sort(key=lambda x: x[0])
        return b"".join(c for _, c in chunks)

    def resp_bodies(stream: bytes):
        """顺序解析 HTTP/1.1 响应流 → body 列表（chunked + gzip 已解）。"""
        bodies = []
        i = 0
        while True:
            m = re.search(rb"HTTP/1\.[01] \d{3}[^\r\n]*\r\n", stream[i:])
            if not m:
                break
            hstart = i + m.end()
            hend = stream.find(b"\r\n\r\n", hstart)
            if hend < 0:
                break
            headers = stream[hstart:hend].lower()
            body_start = hend + 4
            if b"transfer-encoding: chunked" in headers:
                raw = stream[body_start:]
                out = b""
                j = 0
                while j < len(raw):
                    k = raw.find(b"\r\n", j)
                    if k < 0:
                        break
                    try:
                        size = int(raw[j:k].strip().split(b";")[0], 16)
                    except ValueError:
                        break
                    if size == 0:
                        break
                    out += raw[k + 2:k + 2 + size]
                    j = k + 2 + size + 2
                body = out
                z = stream.find(b"0\r\n\r\n", body_start)
                i = z + 5 if z >= 0 else len(stream)
            else:
                mcl = re.search(rb"content-length:\s*(\d+)", headers)
                if mcl:
                    clen = int(mcl.group(1))
                    body = stream[body_start:body_start + clen]
                    i = body_start + clen
                else:
                    body = stream[body_start:]
                    i = len(stream)
            if body[:2] == b"\x1f\x8b":
                try:
                    body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                except zlib.error:
                    pass
            bodies.append(body)
        return bodies

    pairs = []
    n_get = 0
    for v in conns.values():
        c = asm(v["c"])
        if b"GET /?id=" not in c:
            continue
        urls = [urllib.parse.unquote(mm.group(1).decode("latin1"))
                for mm in re.finditer(rb"GET (/\?id=\S+) HTTP/1\.1", c)]
        bodies = resp_bodies(asm(v["s"]))
        n_get += len(urls)
        pairs.extend(zip(urls, bodies))
    return pairs, n_get


def _robust_decode(probes):
    """0..255 上 argmin 冲突数：c(v)=Σ(true 且 thr>=v)+Σ(false 且 thr<v)。"""
    best, best_v = None, 0
    for v in range(256):
        c = sum(1 for t, tr in probes if tr and t >= v) \
            + sum(1 for t, tr in probes if not tr and t < v)
        if best is None or c < best:
            best, best_v = c, v
    return best_v, best


def main() -> int:
    if not os.path.exists(PCAP):
        print("FAIL: 10735 附件缺失\n"
              f"  expect: {PCAP}\n"
              f"  7z:     {SEVEN_ZIP}")
        return 2
    if not os.path.exists(SEVEN_ZIP):
        print(f"FAIL: 完整版 7z.exe 缺失（需支持 RAR5）：{SEVEN_ZIP}")
        return 2

    pairs, n_get = _load_pairs(PCAP)
    # 逐 (字段,行,位) 收集 (thr, is_true)
    probes: dict = defaultdict(list)
    n_true = 0
    n_pred = 0
    for url, body in pairs:
        is_true = body.rstrip().endswith(b"success")
        if is_true:
            n_true += 1
        m = _PRED_PAT.search(url)
        if not m:
            continue
        n_pred += 1
        expr, lim, pos, thr = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
        probes[(_field_of(expr), lim, pos)].append((thr, is_true))
    if n_pred < 2000 or n_true < 500:
        print(f"FAIL: 盲注流量形态异常 n_get={n_get} pairs={len(pairs)} "
              f"pred={n_pred} true={n_true}")
        return 3

    # 解码各字段
    fields: dict = defaultdict(dict)  # field -> {row: str}
    worst_conflict = 0
    for (field, lim, pos), ths in probes.items():
        v, c = _robust_decode(ths)
        worst_conflict = max(worst_conflict, c)
        fields[field][lim or "0"] = fields[field].get(lim or "0", "") + chr(v)

    content = (fields.get("content", {}).get("0", "") or "").split("\x00", 1)[0]
    password = (fields.get("password", {}).get("0", "") or "").split("\x00", 1)[0]
    content_hex_sha = hashlib.sha256(content.encode("ascii", "replace")).hexdigest()
    if content_hex_sha != CONTENT_HEX_SHA256:
        print(f"FAIL: content hex 还原失配\n"
              f"  got len={len(content)} sha256={content_hex_sha}\n"
              f"  expect sha256={CONTENT_HEX_SHA256}（归档 RAR hex 转录一致锚）")
        return 4
    try:
        rar = bytes.fromhex(content)
    except ValueError as exc:
        print(f"FAIL: content 非合法 hex：{exc}")
        return 4
    if hashlib.sha256(rar).hexdigest() != RAR_SHA256:
        print("FAIL: rar 字节 sha256 失配（≠ 归档 logbool.rar）")
        return 4

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RAR_OUT, "wb") as f:
        f.write(rar)

    # 7z 带密码解压（stdout 重定向到日志文件，避免管道 broken pipe / SIGPIPE）
    extract_dir = os.path.join(RESULTS_DIR, "out")
    log_path = os.path.join(RESULTS_DIR, "7z.log")
    cmd = [SEVEN_ZIP, "x", "-y", f"-p{password}", f"-o{extract_dir}", RAR_OUT]
    try:
        with open(log_path, "wb") as lf:
            r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, timeout=120)
    except subprocess.TimeoutExpired:
        print("FAIL: 7z 解压超时")
        return 5

    flag_path = os.path.join(extract_dir, "flag.txt")
    if r.returncode != 0 or not os.path.exists(flag_path):
        print(f"FAIL: 7z 解压失败 rc={r.returncode}（密码推导或工具链异常）")
        return 5
    flag = open(flag_path, "rb").read()
    flag_sha = hashlib.sha256(flag).hexdigest()
    if len(flag) != FLAG_LEN or flag_sha != FLAG_SHA256:
        print(f"FAIL: flag.txt 失配 len={len(flag)} sha256={flag_sha}\n"
              f"  expect len={FLAG_LEN} sha256={FLAG_SHA256}")
        return 6

    print(json.dumps({
        "ok": True,
        "via": "pcap->HTTP重组->sqlmap布尔盲注谓词解析->鲁棒解码->RAR5+密码->7z解压",
        "stats": {"pairs": len(pairs), "n_get": n_get, "pred": n_pred,
                  "true_bodies": n_true, "worst_conflict": worst_conflict,
                  "password_len": len(password)},
        "content_hex_sha256": content_hex_sha,
        "rar_size": len(rar),
        "rar_sha256": hashlib.sha256(rar).hexdigest(),
        "flag_len": len(flag),
        "flag_sha256": flag_sha,
        "flag_note": (
            "flag 字符串不落 verifier 输出/不入 git。flag.txt sha256=67f3e126… 与台账 "
            "2026-08-24 记录前缀 67f3e126d51a6169 + 归档 _10735_unrar/flag.txt 逐字节 "
            "一致（双独立运行交叉互证）；但题面无 flag_sha256 官方字段、无外部真值闭环，"
            "故不进 PROMOTION_EVIDENCE，KPI 水位 12 不动"
        ),
    }, ensure_ascii=False, indent=2))
    print("REGRESS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
