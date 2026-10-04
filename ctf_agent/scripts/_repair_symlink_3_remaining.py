# -*- coding: utf-8 -*-
"""定向修复最后 3 道软链接附件缺陷（2026-10-04）。

区别于 `_repair_symlink_attachments.py`（依赖全量 tree API，本机 14MB 响应会
IncompleteRead 截断），本脚本**不拉全量树**，而是对每道题用已知的精确路径
（由软链接目标 + source_repo 的 ch_dir 还原）直接 raw 下载，带重试抗本机
连接不稳定（ConnectionReset/Timeout）。

三道题与修法（均为 google-ctf 仓库）：
 1. enigma (crypto, 2022/quals/crypto-enigma)
    5 个文件软链 -> ../xxx，2 个目录软链 -> ../enigma(7文件) + ../messages(29文件)
    全部是解题素材（机器源码 + 已知明文/密文），不含 flag 明文（flag 明文在
    题目录 flag/、flag2/，不在 attachments 软链目标内）。
 2. electric-mayhem-pqc (crypto, 2022/quals/crypto-electric-mayhem-pqc)
    elmo.tgz(118KB) 可修；firmware.tgz(6.4MB)/traces.json.gz(14.7MB) 超 1.5MB
    体积政策 -> 跳过（保持 NO_INPUT 诚实记账）。
 3. ican-tbelieveit (misc, 2021/quals/misc-steps)
    chal.py -> challenge/chal.py -> third_party/steps/chal.py（链式软链，真实文件）

反注水约束：
 * 精确跟随软链目标，绝不递归 challenge/ 或题目录整层（避免把 flag/flag.txt
   明文答案卷进来）。
 * 下载后字节级校验：内容不得以 'CTF{' / 'flag{' 明文开头（粗校验，防误下答案）。
 * messages 里的 flag.ciphertext.txt 是「待解的密文」，是合法附件（选手要解的
   就是它），不在排除名单；排除名单只针对明文答案文件（plaintext/original 中
   恰好等于 flag 的，但 enigma 的 flag 明文不在 messages，故无需额外排除）。
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POOL = ROOT / "data" / "questions_external"
REPO = "google/google-ctf"
BRANCH = "main"
RAW = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/" + "{path}"
MAX_FILE_MB = 1.5
MAX_BYTES = int(MAX_FILE_MB * 1024 * 1024)

# 明文 flag 前缀（粗校验：附件内容若以这些开头即视为疑似答案，跳过）
FLAG_PREFIXES = (b"CTF{", b"flag{", b"Flag{", b"FLAG{")


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def raw(op, path: str, retries: int = 4, timeout: int = 40) -> bytes | None:
    """带重试的 raw 下载，抗本机连接不稳定。"""
    url = RAW.format(path=urllib.parse.quote(path, safe="/"))
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ctf-repair"})
            with op.open(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            if i == retries - 1:
                print(f"    ✗ {path}: {type(e).__name__}（重试 {retries} 次失败）")
                return None
            time.sleep(1.5 * (i + 1))
    return None


def looks_like_path_text(data: bytes) -> bool:
    try:
        t = data.decode("ascii").strip()
    except Exception:  # noqa: BLE001
        return False
    return bool(t) and " " not in t and (
        t.startswith("../") or t.startswith("./") or t.startswith("/"))


def write_attachment(op, qid: str, cat: str, rel_name: str, real_path: str,
                     apply: bool, stats: dict) -> None:
    """下载真实文件并写回 _attachments/，带反注水字节校验。"""
    blob = raw(op, real_path)
    if blob is None:
        stats["fetch_fail"] += 1
        return
    if looks_like_path_text(blob) and len(blob) < 64:
        stats["still_text"] += 1
        print(f"    ✗ {rel_name}: 目标仍是路径文本 {blob!r}")
        return
    if len(blob) > MAX_BYTES:
        stats["over_size"] += 1
        print(f"    ⊘ {rel_name}: 超 {MAX_FILE_MB}MB ({len(blob)}B)")
        return
    # 反注水：内容若疑似明文 flag 开头则跳过（粗校验）
    head = blob[:32].lstrip()
    if head.startswith(FLAG_PREFIXES):
        stats["flag_leak"] += 1
        print(f"    ⊘ {rel_name}: 疑似明文 flag 内容，跳过（反注水）")
        return
    dest = POOL / cat / qid / "_attachments" / rel_name
    if apply:
        # 若 rel_name 的某个中间路径是「软链接路径文本伪文件」（抓取器历史落盘的
        # 垃圾），先删掉它，否则 mkdir 会 FileExistsError（如 enigma 的目录软链
        # enigma/、messages/ 曾以 9B/11B 伪文件形态存在）。
        cur = POOL / cat / qid / "_attachments"
        for seg in Path(rel_name).parts[:-1]:
            cur = cur / seg
            if cur.exists() and cur.is_file():
                cur.unlink()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)
    stats["repaired"] += 1
    print(f"    ✓ {rel_name}: {len(blob)}B <- {real_path}")


def repair_enigma(op, apply: bool, stats: dict) -> None:
    qid, cat, ch = "ext_gctf2022_enigma", "crypto", "2022/quals/crypto-enigma"
    print(f"\n[1/3] enigma ({ch})")
    # 5 个文件软链
    files = [".bazelrc", "README.md", "WORKSPACE", "encode.py", "encrypt_modern.py"]
    for f in files:
        write_attachment(op, qid, cat, f, f"{ch}/{f}", apply, stats)
    # enigma/ 目录（7 文件）
    for f in ["BUILD", "Makefile", "enigma.h", "machine.cc",
              "plugboard.h", "reflector.h", "rotors.h"]:
        write_attachment(op, qid, cat, f"enigma/{f}", f"{ch}/enigma/{f}", apply, stats)
    # messages/ 目录（含待解 flag.ciphertext.txt 密文，是合法附件；按天组织）。
    # 注意：may_12(may_14) 只有 flag(flag2) 密文，**没有 settings 文件**（已实测）。
    # 注意：may_12(may_14) 只有 flag(flag2) 密文，**没有 settings 文件**（已实测）。
    days = {
        "may_09_2022": ["comet.ciphertext.txt", "comet.fernet.txt",
                        "comet.original.txt", "comet.plaintext.txt", "settings"],
        "may_10_2022": ["Sidsel_Langroeckchen.ciphertext.txt",
                        "Sidsel_Langroeckchen.fernet.txt",
                        "Sidsel_Langroeckchen.original.txt",
                        "Sidsel_Langroeckchen.plaintext.txt", "settings"],
        "may_11_2022": ["Der_Einzige.ciphertext.txt", "Der_Einzige.fernet.txt",
                        "Der_Einzige.original.txt", "Der_Einzige.plaintext.txt",
                        "settings"],
        # may_12/may_14 的 flag/flag2 密文在 messages 里是**软链**，指向
        # ../../flag/flag.ciphertext.txt 等（真实密文，合法附件）。这里直接给
        # 真实密文路径，绝不带 flag.plaintext.txt（明文答案在 flag/ 目录）。
        "may_13_2022": ["africa.ciphertext.txt", "africa.fernet.txt",
                        "africa.original.txt", "africa.plaintext.txt", "settings"],
        "may_15_2022": ["schuljahresabschluss.ciphertext.txt",
                        "schuljahresabschluss.fernet.txt",
                        "schuljahresabschluss.original.txt",
                        "schuljahresabschluss.plaintext.txt", "settings"],
    }
    for day, names in days.items():
        for f in names:
            rel = f"messages/{day}/{f}"
            write_attachment(op, qid, cat, rel, f"{ch}/messages/{day}/{f}",
                             apply, stats)
    # flag/flag2 密文（messages 里的软链最终落点，均为密文非明文）
    for f, real in [("flag.ciphertext.txt", "flag/flag.ciphertext.txt"),
                    ("flag.fernet.txt", "flag/flag.fernet.txt"),
                    ("flag2.ciphertext.txt", "flag2/flag2.ciphertext.txt"),
                    ("flag2.fernet.txt", "flag2/flag2.fernet.txt")]:
        day = "may_12_2022" if f.startswith("flag.") else "may_14_2022"
        rel = f"messages/{day}/{f}"
        write_attachment(op, qid, cat, rel, f"{ch}/{real}", apply, stats)


def repair_electric_mayhem(op, apply: bool, stats: dict) -> None:
    qid, cat, ch = "ext_gctf2022_electric-mayhem-pqc", "crypto", \
        "2022/quals/crypto-electric-mayhem-pqc"
    print(f"\n[2/3] electric-mayhem-pqc ({ch})")
    # elmo.tgz 118KB 可修；firmware.tgz 6.4MB、traces.json.gz 14.7MB 超限跳过
    write_attachment(op, qid, cat, "elmo.tgz", f"{ch}/challenge/elmo.tgz",
                     apply, stats)
    # 软链 stm32f0_kyber512.json.gz -> ../challenge/traces.json.gz (14.7MB 超限)
    # firmware.tgz (6.4MB 超限)
    print("    ⊘ firmware.tgz / traces.json.gz: 超 1.5MB 体积政策，跳过（NO_INPUT）")


def repair_ican(op, apply: bool, stats: dict) -> None:
    qid, cat, ch = "ext_gctf2021_ican-tbelieveit-snotcrypto", "misc", \
        "2021/quals/misc-steps"
    print(f"\n[3/3] ican-tbelieveit ({ch})")
    # chal.py 是链式断链：attachments/chal.py -> challenge/chal.py ->
    # ../../third_party/steps/chal.py，而 third_party/ 目录在官方仓库**不存在**
    # （已实测 contents API 空目录）。即真实 chal.py 从未提交到公开仓库，
    # 属结构性不可修，保持 NO_INPUT 诚实记账，不凭空捏造附件。
    print("    ⊘ chal.py: 源头断链（challenge/chal.py -> ../../third_party/steps/"
          "chal.py，third_party/ 目录在仓库不存在），结构性不可修，保持 NO_INPUT")


def main() -> int:
    apply = "--apply" in sys.argv
    op = _opener()
    stats = {"repaired": 0, "fetch_fail": 0, "still_text": 0,
             "over_size": 0, "flag_leak": 0}
    repair_enigma(op, apply, stats)
    repair_electric_mayhem(op, apply, stats)
    repair_ican(op, apply, stats)
    print("\n" + "=" * 60)
    print(f"{'实写' if apply else '预演'}统计: {stats}")
    if not apply:
        print("（加 --apply 才会写盘）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
