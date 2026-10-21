"""本地真值基准：生成「flag 不以明文躺在文件里」的真实工件。

为什么需要它（2026-10-20）：
    `benchmarks/external_unseen` 的 50 道真题附件在盘上 0/50，
    `data/questions_real/_attachments` 是空目录 —— 四轮能力建设全部只有适配器级
    合成样本，没有一次「工件 → 工具 → flag」的完整链路验证，更没有召回率。

    本脚本生成的工件全部满足一条约束：**flag 不直接明文躺在容器里**，
    必须走对应能力才能拿到。这样召回才有意义。

    - pcap_br      : HTTP 响应正文 br 压缩，flag 在解压后正文里（须 _inflate）
    - pe_upx       : PE 节区内含 flag，整体被 UPX -9 打包（须脱壳后才发现）
    - wasm_data    : wasm 数据段字符串（须解析 data segment）

    三者都是**合成工件**（provenance=self_authored_training），用来证明机制与召回，
    不代表竞赛真题难度 —— 报告里必须如实标注这一点。

用法：
    python benchmarks/local_real/build_artifacts.py            # 生成全部
    python benchmarks/local_real/build_artifacts.py --only pcap_br
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_HERE = os.path.dirname(os.path.abspath(__file__))
_ART = os.path.join(_HERE, "artifacts")
_MANIFEST = os.path.join(_HERE, "manifest.json")

#: 合成 flag 的种子 → flag 由种子派生，源码里不出现完整明文
_SEEDS = {
    "pcap_br": "pcap-br-body",
    "pe_upx": "pe-upx-section",
    "wasm_data": "wasm-data-seg",
}

#: PE 改造用的宿主二进制（1.1MB，含长字符串段；只需可被 Ghidra 解析，不要求可执行）
_HOST_PE = r"C:\Windows\System32\mstsc.exe"
_UPX = os.environ.get("UPX_EXE", r"E:\Program\tools\upx-5.2.1-win64\upx.exe")
_WAT2WASM = os.path.join(os.environ.get("WABT_BIN", r"E:\Program\tools\wabt-1.0.42\bin"),
                         "wat2wasm.exe")


def synth_flag(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return "flag{" + "synth_" + seed.replace("-", "_") + "_" + h + "}"


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── 工件 1：br 压缩正文的 HTTP 抓包 ──────────────────────────────────────
def build_pcap_br(out_path: str, flag: str) -> dict:
    import brotli
    from scapy.all import IP, TCP, Raw, wrpcap

    html = ("<html><head><title>report</title></head><body>"
            f"<p>build ok</p><p>{flag}</p></body></html>").encode()
    body = brotli.compress(html)
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Content-Encoding: br\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")

    seq_c, seq_s = 1000, 5000
    req = b"GET /report.html HTTP/1.1\r\nHost: intranet.local\r\n\r\n"
    pkts = [
        IP(src="10.9.1.7", dst="10.9.1.80") / TCP(sport=49711, dport=80, flags="S", seq=seq_c),
        IP(src="10.9.1.80", dst="10.9.1.7") / TCP(sport=80, dport=49711, flags="SA",
                                               seq=seq_s, ack=seq_c + 1),
        IP(src="10.9.1.7", dst="10.9.1.80") / TCP(sport=49711, dport=80, flags="PA",
                                                 seq=seq_c + 1) / Raw(load=req),
        # 响应头与正文分两段（真实抓包常态），正文再从中间切一刀
        IP(src="10.9.1.80", dst="10.9.1.7") / TCP(sport=80, dport=49711, flags="PA",
                                                 seq=seq_s) / Raw(load=head),
        IP(src="10.9.1.80", dst="10.9.1.7") / TCP(sport=80, dport=49711, flags="PA",
                                                 seq=seq_s + len(head)) / Raw(load=body[:len(body) // 2]),
        IP(src="10.9.1.80", dst="10.9.1.7") / TCP(sport=80, dport=49711, flags="PA",
                                                 seq=seq_s + len(head) + len(body) // 2) / Raw(load=body[len(body) // 2:]),
    ]
    wrpcap(out_path, pkts)
    return {"hiddenBy": "br 压缩正文", "factory": "scapy", "bytes": os.path.getsize(out_path)}


# ── 工件 2：UPX 打包的 PE（flag 在被压缩的节区里）──────────────────────
def build_pe_upx(out_path: str, flag: str) -> dict:
    if not os.path.isfile(_HOST_PE):
        raise FileNotFoundError(f"宿主 PE 不存在：{_HOST_PE}")
    from tools.adapters.rea_probe import _pe_sections, _pe_section_names

    data = open(_HOST_PE, "rb").read()
    raw = bytearray(data)
    # flag 必须落在**会被压进壳里的节**（.rdata/.text）。两条实测教训：
    #   1. 文件尾附加（overlay）不行：UPX 把 overlay 原样拷进壳里，仍能明文扫到；
    #   2. 落在 .rsrc 也不行：UPX 不压缩资源节，同样明文可见。
    names = _pe_section_names(data)
    _, secs = _pe_sections(data)
    fb = flag.encode()
    off = None
    for want in (".rdata", ".text", ".data"):
        for i, (va, size, ptr) in enumerate(secs):
            if i < len(names) and names[i] == want:
                lo, hi = ptr, ptr + max(0, size - len(fb))
                for m in re.finditer(rb"[\x20-\x7e]{%d,}" % (len(fb) + 8), data[lo:hi]):
                    off = lo + m.start()
                    break
        if off is not None:
            break
    if off is None:
        raise RuntimeError("宿主 PE 的可压缩节里没有足够长的可打印串，换一个宿主二进制")
    raw[off:off + len(fb)] = fb
    tmp = out_path + ".tmp"
    open(tmp, "wb").write(raw)
    # --force：mstsc.exe 带 GUARD_CF，UPX 默认拒绝（CantPackException）；
    # 本工件只要求可被 Ghidra 解析，不要求可执行，故强制打包。
    r = subprocess.run([_UPX, "--force", "-q", "-9", tmp],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        os.replace(tmp, out_path)
        raise RuntimeError(f"upx 打包失败 rc={r.returncode}: {(r.stderr or r.stdout)[:300]}")
    os.replace(tmp, out_path)

    # 前提自检：打包后必须扫不到，脱壳后必须扫得到。否则这个工件证明不了「必须脱壳」。
    from tools.adapters.rea_probe import _rawscan, _unpack_upx

    packed_hits = [h["value"] for h in _rawscan(out_path)[0]]
    if any(flag in v for v in packed_hits):
        raise RuntimeError("打包后 flag 仍是明文（落在未被压缩的节区）—— 工件无效")
    unpacked, ev = _unpack_upx(out_path)
    if not unpacked or not any(flag in h["value"] for h in _rawscan(unpacked)[0]):
        raise RuntimeError(f"脱壳后仍扫不到 flag（unpack={ev.get('ok')}）—— 工件无效")
    return {"hiddenBy": "UPX -9 打包（flag 位于被压缩的 .rdata/.text 节）",
            "host": os.path.basename(_HOST_PE), "patchedOffset": hex(off),
            "rawScanBeforeUnpack": len(packed_hits),
            "bytes": os.path.getsize(out_path)}


# ── 工件 3：wasm 数据段字符串 ───────────────────────────────────────────
def build_wasm_data(out_path: str, flag: str) -> dict:
    if not os.path.isfile(_WAT2WASM):
        raise FileNotFoundError(f"wat2wasm 不存在：{_WAT2WASM}")
    # flag 拆成两段相邻 data segment：明文扫描（flag_scan / strings）拼不出来，
    # 必须真正读 wasm 的数据段布局才能还原。第一版把整串放在一个 data segment 里，
    # 结果被 presolve 的明文扫描 0.0s 直出（0 步、没调 wasm_probe），等于没测到
    # wasm 通道。拆开后 adapter 级只要求「两段都在输出里」，agent 级要求整串。
    half = len(flag) // 2
    a, b = flag[:half], flag[half:]
    wat = f"""(module
  (import "env" "check" (func $check (param i32)))
  (memory (export "mem") 1)
  (data (i32.const 1024) "{a}")
  (data (i32.const {1024 + len(a)}) "{b}")
  (func (export "verify") (result i32)
    (call $check (i32.const 1024))
    (i32.const 1))
)
"""
    wat_path = out_path + ".wat"
    with open(wat_path, "w", encoding="utf-8") as f:
        f.write(wat)
    r = subprocess.run([_WAT2WASM, wat_path, "-o", out_path],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"wat2wasm 失败 rc={r.returncode}: {(r.stderr or r.stdout)[:200]}")
    return {"hiddenBy": "wasm 数据段（flag 拆成两段相邻 segment）",
            "factory": "wat2wasm", "bytes": os.path.getsize(out_path),
            "splitFlag": True}


# ── 题面（不泄漏 flag，只给定位线索）────────────────────────────────────
_CASES = {
    "pcap_br": {
        "category": "misc",
        "title": "流量分析：压缩的报表",
        "description": ("附件是一份 HTTP 抓包。服务端返回的报表页面被压缩传输，"
                        "正文里有一段 flag。flag 格式 flag{}"),
    },
    "pe_upx": {
        "category": "reverse",
        "title": "逆向：被压缩的可执行文件",
        "description": ("附件是一个 Windows PE，flag 作为字符串常量写在某个节区里。"
                        "flag 格式 flag{}"),
    },
    "wasm_data": {
        "category": "reverse",
        "title": "逆向：wasm 校验器",
        "description": ("附件是一个 WebAssembly 模块，校验用的字符串放在数据段里。"
                        "flag 格式 flag{}"),
    },
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="只生成某个 case")
    ap.add_argument("--out", default=_ART)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    builders = {
        "pcap_br": ("capture.pcap", build_pcap_br),
        "pe_upx": ("packed.exe", build_pe_upx),
        "wasm_data": ("checker.wasm", build_wasm_data),
    }
    cases = {}
    # 保留已有 manifest 的其它条目，支持 --only 增量
    if os.path.isfile(_MANIFEST):
        try:
            cases = json.load(open(_MANIFEST, encoding="utf-8")).get("cases", {})
        except Exception:
            cases = {}

    for cid, (fname, fn) in builders.items():
        if args.only and cid != args.only:
            continue
        flag = synth_flag(_SEEDS[cid])
        # 每个 case 单独一个目录：flag_scan 会把**同目录兄弟文件**一并扫
        # （为兼容「附件只有 coso.js、真 flag 在兄弟 index.html」的真题），
        # 三个工件放同一目录会互相污染——实测跑 pcap 题直接返回了 wasm 题的 flag。
        case_dir = os.path.join(os.path.abspath(args.out), cid)
        os.makedirs(case_dir, exist_ok=True)
        path = os.path.join(case_dir, fname)
        info = fn(path, flag)
        cases[cid] = {
            "id": f"localreal_{cid}",
            "category": _CASES[cid]["category"],
            "title": _CASES[cid]["title"],
            "description": _CASES[cid]["description"],
            "artifact": path,
            "flagSha256": sha256_text(flag),
            "provenance": "self_authored_training",
            **info,
        }
        print(f"[{cid}] {path}  {info['bytes']:,} B  hiddenBy={info['hiddenBy']}")

    payload = {
        "_note": ("合成工件基准：flag 不以明文躺在容器里，须走对应能力才能拿到。"
                  "仅证明机制与召回，不代表竞赛真题难度。"),
        "generatedBy": "benchmarks/local_real/build_artifacts.py",
        "cases": cases,
    }
    # 必须走统一写入口：benchmarks/ 下的 JSON 由 tests/test_truth_guard.py 审计，
    # 要求 schema + written_by 可溯源（自己 open().write() 会被判定绕过守卫）。
    from pathlib import Path as _Path

    from scripts._truth_guard import write_truth

    write_truth(_Path(_MANIFEST), payload, schema="local_real_manifest/v1",
                by="benchmarks/local_real/build_artifacts.py")
    print(f"manifest → {_MANIFEST}（{len(cases)} case，仅存 sha256，不存明文）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
