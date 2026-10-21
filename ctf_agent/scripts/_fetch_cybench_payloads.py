"""从公开的 Cybench 仓库拉取真题发布件，补上外部基准缺失的载荷。

为什么需要这个脚本
------------------
`benchmarks/external_unseen` 的 50 题只有一个 sha256 真值，附件路径全部指向
`data/questions_ext_cybench/_attachments/...`，而该目录在盘上是空的（0/50）。
没有载荷，这 50 题就只能当摆设；有了载荷，`flag_sha256` 就是可机器判分的地面真值。

口径红线
--------
1. **只取 `release/` 下的发布件**。仓库里同时存在 `metadata/solution/`（含官方解答、
   打过补丁的二进制、甚至明文 flag），那是答案泄漏源，一行都不下载。
2. 只下载题面 `attachments` 里声明过的文件名，其余一律不碰。
3. 下载后按 sha256 记账（`_payloads.lock.json`），供复算与漂移检测。
4. 落盘前扫描明文 `HTB{...}`，命中即判定「答案泄漏」，拒绝写入。

完整性怎么判
------------
仓库树（GitHub tree API）给出每个 blob 的精确字节数，这是最强的离线口径：字节数
不符就是坏载荷。魔数只作附加检查，且**能省则省** —— 实测 `message.txt.cz` 头 32
字节全零，它是自定义压缩格式的正常头部，按「必须是可执行文件」判会误杀真载荷。

用法
----
    python scripts/_fetch_cybench_payloads.py            # 下载缺失的
    python scripts/_fetch_cybench_payloads.py --check     # 只校验，不下载
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass

# lock 是机器真值：写入必须经 truth guard 登记 schema（2026-10-21 门禁教训：
# 直接 write_text 产出的文件没有 schema，审计即红）
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
from _truth_guard import write_truth

_LOCK_SCHEMA = "external_payloads_lock/v1"

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = "andyzorigin/cybench"
#: 钉住 commit：上游改目录/换版本都不该悄悄改变我们的判分基准
_COMMIT = "ca483c6443f17a20ba7d6bac3d274859a1721e51"
_RAW = f"https://raw.githubusercontent.com/{_REPO}/{_COMMIT}/"
_LOCK = os.path.join(_ROOT, "benchmarks", "external_unseen", "_payloads.lock.json")

_SHA_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


def _normalize_lock(raw) -> dict:
    """把任意历史形态的 lock 归一成 {qid: {name: sha256}}。

    判据是**值形态**而不是键名：任何一层里「值是 {文件名: 64位hex}」的 dict
    就是 qid 表的一层，递归合并。repo/commit/payloads 这些包装键自然被跳过
    （它们的值不是 sha 表）。合并而非覆盖：同一 qid 在不同层出现过时取并集，
    以磁盘上最后出现的为准（dict.update 语义）。
    """
    out: dict = {}

    def walk(node) -> None:
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if not isinstance(v, dict) or not v:
                continue
            if all(isinstance(s, str) and _SHA_RE.match(s) for s in v.values()):
                out.setdefault(k, {}).update(v)
            else:
                walk(v)

    walk(raw)
    return out


@dataclass(frozen=True)
class Payload:
    qid: str
    repo_path: str          # 仓库内路径（仅 release/ 发布件）
    name: str               # 落盘文件名
    size: int | None        # 仓库树声明的字节数；None = zip 内层文件，树里查不到
    magic: bytes | None     # 可选魔数，None 表示该格式没有可靠魔数
    cat: str = "rev"        # 落盘一级目录（external_unseen 声明路径用，非 rev 题必须显式给）


#: 落盘目录沿用 external_unseen 里声明的相对路径，避免两套路径打架
#: 2026-10-21 收尾轮补全：external_unseen 50 题里有 13 个附件（6 题）不在盘，
#: 经 `gh api .../git/trees/<commit>?recursive=1` 发现真实路径后逐条登记。
#: 字节数全部取自钉死 commit 的树（最强离线口径）；zip 内层文件树里查不到，
#: 按 PackedAway 先例走解包。**只取 challenge/ 与 release/，不碰 metadata/solution/
#: 与 htb/solver.py**——那是答案泄漏源。
_HTB = "benchmark/hackthebox/cyber-apocalypse-2024"
_SEKAI = "benchmark/project-sekai-ctf"
_PLAN = [
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_reversing_very_easy_packedaway",
            f"{_HTB}/reversing/[Very Easy] PackedAway/"
            "release/rev_packedaway.zip", "packed", None, b"\x7fELF"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_reversing_easy_crushing",
            f"{_HTB}/reversing/[Easy] Crushing/"
            "htb/rev_crushing/crush", "crush", 16872, b"\x7fELF"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_reversing_easy_crushing",
            f"{_HTB}/reversing/[Easy] Crushing/"
            "htb/rev_crushing/message.txt.cz", "message.txt.cz", 8784, None),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_reversing_hard_flecksofgold",
            f"{_HTB}/reversing/[Hard] FlecksOfGold/"
            "release/rev_flecksofgold/flecks", "flecks", 1089896, b"\x7fELF"),
    # ── crypto（HTB CA24）──
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_hard_permuted",
            f"{_HTB}/crypto/[Hard] Permuted/challenge/output.txt",
            "output.txt", 1016834, None, cat="crypto"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_hard_permuted",
            f"{_HTB}/crypto/[Hard] Permuted/challenge/source.py",
            "source.py", 1590, None, cat="crypto"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_medium_partial_tenacity",
            f"{_HTB}/crypto/[Medium] Partial Tenacity/challenge/output.txt",
            "output.txt", 740, None, cat="crypto"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_medium_partial_tenacity",
            f"{_HTB}/crypto/[Medium] Partial Tenacity/challenge/source.py",
            "source.py", 626, None, cat="crypto"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_very_easy_dynastic",
            f"{_HTB}/crypto/[Very Easy] Dynastic/challenge/output.txt",
            "output.txt", 216, None, cat="crypto"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_very_easy_dynastic",
            f"{_HTB}/crypto/[Very Easy] Dynastic/challenge/secret.py",
            "secret.py", 83, None, cat="crypto"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_crypto_very_easy_dynastic",
            f"{_HTB}/crypto/[Very Easy] Dynastic/challenge/source.py",
            "source.py", 631, None, cat="crypto"),
    # ── forensics（HTB CA24，发布件是 zip，取内层）──
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_forensics_very_easy_it_has_begun",
            f"{_HTB}/forensics/[Very Easy] It Has Begun/release/forensics_it_has_begun.zip",
            "script.sh", None, None, cat="forensics"),
    Payload("ext_cybench_hackthebox_cyber_apocalypse_2024_forensics_very_easy_urgent",
            f"{_HTB}/forensics/[Very Easy] Urgent/release/forensics_urgent.zip",
            "Urgent Faction Recruitment Opportunity - Join Forces Against KORP\u2122 Tyranny.eml",
            None, None, cat="forensics"),
    # ── crypto（Project Sekai CTF，与 HTB 不同源目录）──
    Payload("ext_cybench_project_sekai_ctf_sekaictf_2022_crypto_diffecient",
            f"{_SEKAI}/sekaictf-2022/crypto/diffecient/challenge/Dockerfile",
            "Dockerfile", 371, None, cat="crypto"),
    Payload("ext_cybench_project_sekai_ctf_sekaictf_2022_crypto_diffecient",
            f"{_SEKAI}/sekaictf-2022/crypto/diffecient/challenge/xinetd",
            "xinetd", 267, None, cat="crypto"),
    Payload("ext_cybench_project_sekai_ctf_sekaictf_2022_crypto_diffecient",
            f"{_SEKAI}/sekaictf-2022/crypto/diffecient/challenge/app/diffecient.py",
            "diffecient.py", 4221, None, cat="crypto"),
    Payload("ext_cybench_project_sekai_ctf_sekaictf_2023_crypto_randsubware",
            f"{_SEKAI}/sekaictf-2023/crypto/randsubware/metadata/challenge/app/chall.py",
            "chall.py", 9271, None, cat="crypto"),
]


def _dst(p: Payload) -> str:
    rest = p.qid[len("ext_cybench_"):]
    return os.path.join(_ROOT, "data", "questions_ext_cybench", "_attachments",
                        p.cat, rest, p.name)


def _get(url: str, attempts: int = 3) -> bytes:
    """下载；raw.githubusercontent 偶发 ConnectionReset/挂起（本轮各遇到一次）。"""
    last: Exception | None = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ctf-agent/payload-fetch"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001 - 网络抖动一律重试，最终如实抛出
            last = exc
            print(f"    ! 第 {i + 1} 次失败：{type(exc).__name__}")
    raise RuntimeError(f"下载失败 {url}: {last}")


def _extract_from_zip(blob: bytes, want: str) -> bytes:
    """从 release zip 里取出目标文件；找不到就如实报错，不猜。"""
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = [n for n in z.namelist() if os.path.basename(n) == want]
        if not names:
            raise RuntimeError(f"zip 内没有 {want}，实际条目={z.namelist()[:8]}")
        return z.read(names[0])


def _leaks_flag(blob: bytes) -> str | None:
    """发布件里不该出现明文 flag；命中说明取错了文件（多半是 solution/）。"""
    m = re.search(rb"HTB\{[^}\r\n]{1,120}\}", blob)
    return m.group(0).decode("latin-1") if m else None


def _verify(p: Payload, blob: bytes) -> str | None:
    """返回问题描述，None 表示通过。尺寸优先于魔数（尺寸来自仓库树，最可靠）。"""
    if p.size is not None and len(blob) != p.size:
        return f"字节数不符：期望 {p.size:,}，实际 {len(blob):,}"
    if p.magic is not None and not blob.startswith(p.magic):
        return f"魔数不符：期望 {p.magic!r}，实际 {blob[:4]!r}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只校验磁盘上的载荷与 lock 是否一致")
    args = ap.parse_args()

    lock = {}
    if os.path.isfile(_LOCK):
        with open(_LOCK, encoding="utf-8") as f:
            raw_lock = json.load(f)
        # 落盘结构是 {repo, commit, payloads:{qid:{name:sha}}}；旧的读取口径直接拿
        # 顶层当 qid 表，于是 --check 永远报「lock 无此条目」——写入与读取必须同构。
        # 但**只做一层 .get("payloads") 不够**：历史上写入口径变更多次，盘上出现过
        # payloads→payloads→payloads 三层套娃（每跑一次再套一层，qid 表散落在多层，
        # 同一 qid 在不同层字段还不一样）。所以读取时递归归一：把所有「值是
        # {name: 64位hex}」的层都按 qid 合并，写回时统一成干净的一层。
        lock = _normalize_lock(raw_lock)

    ok = miss = bad = 0
    for p in _PLAN:
        dst = _dst(p)
        if args.check:
            if not os.path.isfile(dst):
                print(f"  ✗ 缺失 {os.path.relpath(dst, _ROOT)}")
                miss += 1
                continue
            blob = open(dst, "rb").read()
            exp = (lock.get(p.qid) or {}).get(p.name)
            problem = _verify(p, blob) or (
                None if exp else "lock 无此条目，无法复算")
            if problem is None and hashlib.sha256(blob).hexdigest() != exp:
                problem = "摘要与 lock 不一致"
            if problem:
                print(f"  ✗ {p.name}: {problem}")
                bad += 1
            else:
                print(f"  ✓ {p.name}  {len(blob):>9,} B  {exp[:16]}")
                ok += 1
            continue

        if os.path.isfile(dst) and os.path.getsize(dst) > 0:
            blob = open(dst, "rb").read()
            problem = _verify(p, blob)
            if problem:
                print(f"  ✗ 已有文件不可用（{problem}）：{p.name}")
                bad += 1
                continue
            digest = hashlib.sha256(blob).hexdigest()
            lock.setdefault(p.qid, {})[p.name] = digest
            print(f"  · 复用已存在 {p.name}  {len(blob):>9,} B  {digest[:16]}")
            ok += 1
            continue

        url = _RAW + urllib.parse.quote(p.repo_path)
        print(f"  ↓ {p.repo_path.split('/cyber-apocalypse-2024/')[-1]}")
        blob = _get(url)
        # 按扩展名判断，不能按「名字是否为路径子串」：`packed` 恰好是
        # `rev_packedaway.zip` 的子串，那种写法会把 zip 本体当成二进制落盘。
        if p.repo_path.lower().endswith(".zip"):
            blob = _extract_from_zip(blob, p.name)
        problem = _verify(p, blob)
        if problem:
            print(f"  ✗ 下载内容不可用（{problem}）：{p.name}")
            bad += 1
            continue
        leak = _leaks_flag(blob)
        if leak:
            print(f"  ✗ 拒绝写入：载荷含明文 {leak[:24]}…（取到了答案文件）")
            bad += 1
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(blob)
        digest = hashlib.sha256(blob).hexdigest()
        lock.setdefault(p.qid, {})[p.name] = digest
        print(f"    → {os.path.relpath(dst, _ROOT)}  {len(blob):,} B  {digest[:16]}")
        ok += 1

    if not args.check and lock:
        # 不走裸 write_text：schema 登记 + written_at/written_by 溯源由守卫统一负责
        write_truth(_LOCK, {"repo": _REPO, "commit": _COMMIT, "payloads": lock},
                    schema=_LOCK_SCHEMA,
                    by="scripts/_fetch_cybench_payloads.py")
        print(f"  lock → {os.path.relpath(_LOCK, _ROOT)}（schema={_LOCK_SCHEMA}）")

    print(f"ok={ok} miss={miss} bad={bad}")
    return 0 if (miss == 0 and bad == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
