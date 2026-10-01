"""答案来源审计（leak provenance）：给题库里每道题判定「真值 flag 究竟从哪来」。

背景（2026-10-01 复盘）：
  上一轮「头对头对比」把 5 道题判成「朴素基线独中 = 本次确定性层的抽取盲区」，
  实则那 5 道全是 **writeup 反推题**，附件就是官方 writeup 全文，真 flag 明文
  躺在里面 —— 基线赢是因为它把文件里所有 flag 形状候选逐一 sha 比对（=grep），
  不是解出来了。这是「反注水」红线，**不是可修的盲区**。

  于是需要一个客观口径：每题的真值 flag 到底「物理上」出现在哪里？
    att_leak   真值明文就在附件里（grep 可得）→ 任何工具的命中都不算实力
    desc_leak  真值明文/内层 token 就在题目描述里（题面即 wp 摘要）→ 同上
    computed   附件与描述都没有真值明文，且 presolve 参照解命中 → 只能靠计算/解码 = 真分析
    unsolved   附件与描述都没有真值明文，且 presolve 参照解**未**命中

  ⚠️ **`unsolved` ≠ 题目不可解**（2026-10-01 交叉审计踩到的坑）：此档只陈述
  「本次 presolve 参照解没命中」。A 类「完整攻击链」题本就不是 presolve 的目标，
  常由专用 verifier 脚本核验（如 `verify_specialcurve2.py`）——`real_crypto_specialcurve2`
  就是此档，但台账状态确为 `✅ offline_verified`。**引用本档时须回台账/verifier 复核，
  不可把 `unsolved` 读成"该题没被解出"。** 交叉审计见 `scripts/_kpi_leak_crossaudit.py`。

  判定只看「真值是否物理存在」，与谁解出无关；这样 presolve / 基线 / 未来
  任何解法的命中率都能被拆成「注水部分 / 实力部分」两块。

  ⚠️ **裸 token 盲区（2026-10-01 二次审计发现并修复）**：首版只按 flag 形状
  （`xxx{...}`）扫附件，于是「答案是不带外壳的裸 token」的题（`145` / `cisco123` /
  `Cisc0` / 裸 md5 / 裸 uuid）被**漏判成 unsolved**，虚增了"干净"分母。修复后新增
  `_bare_token_hit`（精确哈希，无子串误报）——内部 92 池有 **9 道**由 unsolved 纠正
  为 att_leak（`real_misc_sheng2022_traffic_*` ×5、`real_misc_longjian2024_*` ×4）。
  **裸 token 与 flag 形状两条通道都必须生效，否则泄漏会被系统性少报。**

零成本、纯本地、零 LLM。

用法：
    python scripts/_leak_provenance.py --dir data/questions_real
    python scripts/_leak_provenance.py --dir data/questions_real --json ../logs/leak_real92.json
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.cases import load_questions  # noqa: E402

# 尽量宽松：flag 形状（前缀可空、内层可有空格外任意字符）
FLAG_SHAPE = re.compile(rb"[A-Za-z0-9_]{0,16}\{[^}\s\x00-\x1f]{2,200}\}")
_TOKEN = re.compile(r"^[A-Za-z0-9_]{1,16}\{(.*)\}$")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _plaintext_flag(q) -> str | None:
    """拿到该题真值的明文形态（若 JSON 里直接存了明文）；存 sha256 则返回 None。"""
    for k in ("flag", "answer"):
        v = getattr(q, k, None)
        if isinstance(v, str) and v and not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            return v
    return None


def _scan_blob_for(blob: bytes, sha: str) -> list[str]:
    hits = [m.group(0).decode("latin-1")
            for m in FLAG_SHAPE.finditer(blob) if _sha(m.group(0)) == sha]
    return hits


_BARE_WS = re.compile(rb"\s+")
_BARE_MAX_TOKENS = 20000
_BARE_MAX_BYTES = 4_000_000


def _bare_token_hit(blob: bytes, sha: str) -> bool:
    """附件里是否存在「无 {} 外壳」的裸 token，其 sha256 == sha。

    补 `FLAG_SHAPE` 的盲区（2026-10-01 二次审计）：`145` / `cisco123` / `Cisc0` /
    裸 md5 / 裸 uuid 这类答案**没有 flag{...} 外壳**，正则永远匹配不上，但明文
    确实物理躺在附件里（典型：建库时把 `flag.txt` 答案文件误当题目附件挂上）。

    判定只用**精确哈希相等**（整块 strip / 空白切分出的每个 token），
    不做子串匹配，因此除 sha256 碰撞外**无假阳性**；token 数与字节数均有上限，
    大文件不会拖垮。
    """
    if not sha or not blob:
        return False
    if len(blob) <= _BARE_MAX_BYTES and _sha(blob.strip()) == sha:
        return True
    n = 0
    for tok in _BARE_WS.split(blob):
        if not tok:
            continue
        n += 1
        if n > _BARE_MAX_TOKENS:
            return False
        if len(tok) <= 256 and _sha(tok) == sha:
            return True
    return False


def _attachment_plaintext(atts: list[str], sha: str, base: Path) -> tuple[bool, str]:
    """真值明文是否物理出现在附件里。返回 (是否, 哪个文件)。

    先按 flag 形状（`xxx{...}`）扫，再按裸 token 扫（`#bare-token` 后缀标记来源）。
    """
    for a in atts or []:
        p = Path(a)
        if not p.exists():
            p2 = base / Path(a).name
            if p2.exists():
                p = p2
            else:
                hits = list(Path("data").rglob(p.name))
                p = hits[0] if len(hits) == 1 else p
        if not p.exists():
            continue
        try:
            data = p.read_bytes()
        except Exception:  # noqa: BLE001
            continue
        if _scan_blob_for(data, sha):
            return True, p.name
        if _bare_token_hit(data, sha):
            return True, f"{p.name}#bare-token"
        # 归档：内存只读遍历（防 zip-slip）
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for n in zf.namelist():
                        if n.endswith("/") or ".." in n.split("/"):
                            continue
                        try:
                            inner = zf.read(n)
                        except Exception:  # noqa: BLE001
                            continue
                        if _scan_blob_for(inner, sha):
                            return True, f"{p.name}!{n}"
                        if _bare_token_hit(inner, sha):
                            return True, f"{p.name}!{n}#bare-token"
            except Exception:  # noqa: BLE001
                pass
    return False, ""


def classify(q, base: Path, oracle: dict | None = None) -> dict:
    atts = list(getattr(q, "attachments", []) or [])
    sha = getattr(q, "flag_sha256", None) or ""
    plain = _plaintext_flag(q)
    if plain:
        sha = _sha(plain.encode("utf-8"))
    desc = str(getattr(q, "description", "") or "")

    in_att, which = _attachment_plaintext(atts, sha, base) if sha else (False, "")

    # oracle[id] 是别处（presolve 审计）已验证出来的答案明文，用作「描述泄漏」的
    # 内层 token 判据：题面常只写裸答案（如 "解出 CLCKOUTHK"）而不带 flag{...} 外壳。
    if not plain and oracle:
        plain = oracle.get(getattr(q, "id", "?"))

    in_desc = False
    if sha:
        for m in FLAG_SHAPE.finditer(desc.encode("utf-8", "ignore")):
            if _sha(m.group(0)) == sha:
                in_desc = True
                break
        if not in_desc:
            for m in re.finditer(r"[A-Za-z0-9_]{1,16}\{[^}\s]{2,200}\}", desc):
                if _sha(m.group(0).encode()) == sha:
                    in_desc = True
                    break
    if not in_desc and plain and plain in desc:
        in_desc = True
    if not in_desc and plain:
        mt = _TOKEN.match(plain)
        if mt and mt.group(1) and mt.group(1) in desc:
            in_desc = True

    if in_att:
        prov = "att_leak"
    elif in_desc:
        prov = "desc_leak"
    else:
        prov = "none"  # 是否 computed / unsolved 由「是否命中」决定（外部传入）

    return {
        "id": getattr(q, "id", "?"),
        "category": getattr(q, "category", "?"),
        "sha": sha[:12] if sha else "",
        "plaintext_known": bool(plain),
        "in_attachment": in_att,
        "attachment_file": which,
        "in_description": in_desc,
        "provenance": prov,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--json", default="")
    ap.add_argument("--presolve-json", default="",
                    help="可选：_presolve_audit.py 的输出，用其已验证答案作明文 oracle")
    args = ap.parse_args()

    base = Path(args.dir)
    oracle: dict = {}
    hit: set = set()
    if args.presolve_json:
        pj = json.loads(Path(args.presolve_json).read_text(encoding="utf-8"))
        for r in pj.get("rows", []):
            if r.get("with_answers_verdict") == "TRUE" and r.get("with_answers"):
                oracle[r["id"]] = r["with_answers"]
                hit.add(r["id"])

    qs = load_questions(args.dir)
    rows = []
    for q in qs:
        r = classify(q, base, oracle)
        # 落最终档位：物理泄漏优先，否则按「是否被算出」分 computed/unsolved
        if r["provenance"] == "none":
            r["provenance"] = "computed" if r["id"] in hit else "unsolved"
        rows.append(r)

    import collections
    c = collections.Counter(r["provenance"] for r in rows)
    print(f"题库 {args.dir} | {len(rows)} 题")
    print(f"  🔴 att_leak  真值明文在附件里（grep 可得）: {c.get('att_leak', 0)}")
    print(f"  🔴 desc_leak 真值明文/内层 token 在描述里   : {c.get('desc_leak', 0)}")
    print(f"  🟢 computed  附件与描述都没有（真算出）     : {c.get('computed', 0)}")
    print(f"  ⚪ unsolved  未解出且无泄漏                 : {c.get('unsolved', 0)}")

    rep = {"dir": args.dir, "n": len(rows), "summary": dict(c), "rows": rows}
    if args.json:
        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"-> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
