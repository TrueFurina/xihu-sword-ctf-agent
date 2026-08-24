"""直接 skill 执行桥：绕过 LLM agent，确定性调用已验证 skill 解真题。

对每道题：
1. 解压附件 → 提取参数（task.py 源码 / 文件结构 / XOR 线索）
2. 匹配对应 skill
3. 直接调用 skill（不经过 LLM）
4. 提取 flag

用法:
    .venv/Scripts/python.exe scripts/_direct_skill_run.py                    # 全部有 skill 的题
    .venv/Scripts/python.exe scripts/_direct_skill_run.py --ids 10732,10733  # 指定题号
    .venv/Scripts/python.exe scripts/_direct_skill_run.py --web              # web REAL flag_scan
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import re
import struct
import sys
import zipfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("direct_skill")

ATT_DIR = _ROOT / "data" / "race_attachments"


def _find_att(cid: str) -> Path | None:
    """找到题号对应的附件。"""
    for p in ATT_DIR.iterdir():
        if p.name.startswith(f"{cid}_"):
            return p
    return None


def _unzip_to(src: Path, dest: Path, max_size: int = 500 * 1024 * 1024) -> bool:
    """安全解压 zip 到目录。"""
    try:
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(src, "r") as zf:
            total = sum(zi.file_size for zi in zf.infolist())
            if total > max_size:
                logger.warning("解压总大小 %.0fMB 超限 %.0fMB，跳过", total / 1e6, max_size / 1e6)
                return False
            zf.extractall(dest)
        return True
    except Exception as e:
        logger.warning("解压失败 %s: %s", src.name, e)
        return False


# ── CRYPTO-01 (10732): PKCS#1 v1.5 ──────────────────────────────────

def _extract_comment_int(name: str, text: str) -> int | None:
    """从 task.py 注释中提取 print 输出的整数值。

    匹配两种格式：
    - # name: 12345...
    - name= 12345...
    """
    # 格式1: # name: value
    m = re.search(rf'#\s*{name}\s*:\s*(\d+)', text)
    if m:
        return int(m.group(1))
    # 格式2: name= value (在注释块内)
    m = re.search(rf'{name}=\s*(\d+)', text)
    if m:
        return int(m.group(1))
    # 格式3: name: value (注释)
    m = re.search(rf'{name}\s*:\s*(\d+)', text)
    if m:
        return int(m.group(1))
    return None


def solve_10732() -> dict:
    """CRYPTO-01: e=3 低指数攻击 → 解密 AES → PDF flag。

    task.py 注释里有 5 行 print 输出：
    - p (gift)
    - hint_enc
    - n
    - AES_KEY_ENC (RSA加密的AES key整数)
    - pow(AES_KEY_ENC, d, q*r) = padded AES key (RSA解密后的值)
    """
    att = _find_att("10732")
    if not att:
        return {"error": "no attachment"}
    # 外层 zip → 内层 zip
    tmp = _ROOT / "data" / "tmp_dryrun" / "10732"
    if not any(tmp.rglob("task.py")):
        if not _unzip_to(att, tmp):
            return {"error": "outer unzip failed"}
        # 找内层 zip
        inner_zips = list(tmp.rglob("*.zip"))
        for iz in inner_zips:
            inner_tmp = iz.parent / iz.stem
            if not any(inner_tmp.rglob("task.py")):
                _unzip_to(iz, inner_tmp)
    # 找 task.py
    task_py = None
    for p in tmp.rglob("task.py"):
        task_py = p
        break
    if not task_py:
        return {"error": "task.py not found"}
    code = task_py.read_text(encoding="utf-8", errors="ignore")
    logger.info("[10732] task.py found (%d chars)", len(code))
    # 从注释提取 RSA 参数（print 输出值在注释里）
    e = 3  # 代码里 e = 0x3
    n = _extract_comment_int("n", code)
    p_val = _extract_comment_int("My gift for you", code) or _extract_comment_int("p", code)
    hint_enc = _extract_comment_int("hint_enc", code)
    # 最后一行 print 输出的是 pow(bytes_to_long(AES_KEY_ENC), d, q*r) = padded AES key
    # task.py 有 5 行注释输出，最后一行是 RSA 解密后的 padded AES key（无标签）
    all_nums = re.findall(r'(\d{50,})', code)
    if all_nums:
        padded_long = int(all_nums[-1])  # 最后一个大整数 = pow 输出
    else:
        padded_long = None
    logger.info("[10732] e=%d n=%s.. p=%s.. hint_enc=%s.. padded=%s..",
                e, str(n)[:20] if n else "?", str(p_val)[:20] if p_val else "?",
                str(hint_enc)[:20] if hint_enc else "?", str(padded_long)[:20] if padded_long else "?")
    # 找 .enc 文件（AES-ECB 加密的 PDF）
    enc_pdf = None
    for p in tmp.rglob("*.enc"):
        enc_pdf = p
        break
    from skills.crypto_pkcs1_padding_oracle import run as pkcs1_run
    # Step 1: cuberoot hint_enc → hint（如果有的话，用于理解题目）
    if hint_enc and n:
        r1 = pkcs1_run({"kind": "cuberoot", "c": hint_enc, "e": e, "n": n})
        hint_text = r1.get("plaintext", "") or r1.get("text", "")
        logger.info("[10732] cuberoot hint: %s", (hint_text or "")[:80])
    # Step 2: unpad padded_long → AES key
    # padded_long 是 pow(bytes_to_long(AES_KEY_ENC), d, q*r) 的输出
    # 篡改的 PKCS1_v1_5.py 把 PS 全填 0x00，标准 unpad 会在 position 2 命中分隔符
    # 我们的 skill 有 tail-extract 兜底（msg_len=16）
    if not padded_long:
        return {"error": "missing padded_long (AES key decryption output)"}
    # q*r = n // p（如果 p 和 n 已知）
    qr = (n // p_val) if (n and p_val) else 0
    key_bytes = max(128, (qr.bit_length() + 7) // 8) if qr else 128
    r2 = pkcs1_run({"kind": "unpad", "padded_long": padded_long,
                    "key_bytes": key_bytes, "msg_len": 16})
    aes_key_hex = r2.get("msg_hex", "")
    logger.info("[10732] AES key hex: %s (method=%s)", aes_key_hex, r2.get("method", "?"))
    if not aes_key_hex:
        return {"error": "unpad failed", "padded_long_bits": padded_long.bit_length()}
    # Step 3: AES-ECB 解密 PDF
    if not enc_pdf:
        return {"error": "no .enc file found", "aes_key": aes_key_hex}
    out_pdf = tmp / "decrypted.pdf"
    r3 = pkcs1_run({"kind": "aes_ecb", "key": aes_key_hex,
                    "enc_file": str(enc_pdf), "out_file": str(out_pdf)})
    if r3.get("ok"):
        pdf_data = out_pdf.read_bytes() if out_pdf.exists() else b""
        # 搜 flag
        flag_match = re.search(rb'DASCTF\{[^}]+\}', pdf_data)
        if flag_match:
            return {"flag": flag_match.group().decode(), "method": "pkcs1_full_chain", "aes_key": aes_key_hex}
        text = pdf_data.decode("latin-1", errors="ignore")
        flags = re.findall(r'DASCTF\{[^}]+\}', text)
        if flags:
            return {"flag": flags[0], "method": "pkcs1_full_chain", "aes_key": aes_key_hex}
        return {"flag": None, "method": "pkcs1_pdf_no_flag", "aes_key": aes_key_hex,
                "pdf_size": len(pdf_data), "pdf_head": pdf_data[:20].hex() if pdf_data else ""}
    return {"error": f"aes_ecb failed: {r3}", "aes_key": aes_key_hex}


# ── CRYPTO-02 (10733): high exponent RSA ────────────────────────────

def solve_10733() -> dict:
    """CRYPTO-02: e=65536=2^16 高偶指数 RSA。

    task.py 注释里有 print 输出：
    - hint = pow(e*p + e**2, q, n)
    - c = pow(m, e, n)  (加密的 flag)
    - n = p*q
    注意：p 和 q 不在注释输出里（被截断或故意不给）。
    需要用 hint 关系式恢复 p/q，或直接尝试分解 n。
    """
    att = _find_att("10733")
    if not att:
        return {"error": "no attachment"}
    tmp = _ROOT / "data" / "tmp_dryrun" / "10733"
    if not any(tmp.rglob("task.py")):
        if not _unzip_to(att, tmp):
            return {"error": "unzip failed"}
    task_py = None
    for p in tmp.rglob("task.py"):
        task_py = p
        break
    if not task_py:
        for p in tmp.rglob("*.py"):
            task_py = p
            break
    if not task_py:
        return {"error": "task.py not found"}
    code = task_py.read_text(encoding="utf-8", errors="ignore")
    logger.info("[10733] task.py: %d chars", len(code))
    # 从注释提取
    e = 65536  # 代码里写死
    hint = _extract_comment_int("hint", code)
    c = _extract_comment_int("c", code)
    n = _extract_comment_int("n", code)
    p_val = _extract_comment_int("p", code)
    q_val = _extract_comment_int("q", code)
    logger.info("[10733] e=%d hint=%s.. c=%s.. n=%s.. p=%s.. q=%s..",
                e, str(hint)[:20] if hint else "?", str(c)[:20] if c else "?",
                str(n)[:20] if n else "?", str(p_val)[:20] if p_val else "?",
                str(q_val)[:20] if q_val else "?")
    if not n or not c:
        return {"error": f"missing n/c: n={n} c={c}"}
    # 如果有 p 和 q，直接用 high_exponent skill
    if p_val and q_val:
        from skills.crypto_high_exponent import run as he_run
        r = he_run({"kind": "auto", "e": e, "p": p_val, "q": q_val, "c": c, "n": n})
        flag = r.get("flag") or r.get("plaintext") or r.get("text")
        if flag:
            return {"flag": flag, "method": "high_exponent_auto", "detail": r}
        return {"flag": None, "method": "he_miss", "detail": r}
    # 如果只有 n，尝试分解 n（factordb / Fermat / Pollard rho）
    # 或者用 hint 关系式恢复 p, q
    # hint = (e*p + e^2)^q mod n
    # hint mod q = (e*p + e^2) mod q = e*(p+e) mod q
    # hint mod p = (e^2)^q mod p = e^(2q) mod p
    # 尝试：gcd(hint, n) 或 gcd(hint - e^2, n)
    import math
    g1 = math.gcd(hint, n) if hint else 1
    g2 = math.gcd(hint - e * e, n) if hint else 1  # hint - e^2
    logger.info("[10733] gcd(hint, n)=%d gcd(hint-e^2, n)=%d", g1, g2)
    if g1 > 1 and g1 < n:
        p_val = g1
        q_val = n // p_val
        logger.info("[10733] gcd 分解成功: p=%s.. q=%s..", str(p_val)[:20], str(q_val)[:20])
    elif g2 > 1 and g2 < n:
        p_val = g2
        q_val = n // p_val
        logger.info("[10733] gcd(hint-e^2) 分解成功: p=%s.. q=%s..", str(p_val)[:20], str(q_val)[:20])
    else:
        # 尝试 Fermat 分解（p, q 接近时）
        from skills.rsa_fermat_factor import run as fermat_run
        r_f = fermat_run({"n": n, "kind": "fermat", "max_iter": 100000})
        if r_f.get("p"):
            p_val = int(r_f["p"])
            q_val = int(r_f["q"])
            logger.info("[10733] Fermat 分解成功")
        else:
            # 尝试用 hint 恢复：hint = (e*p + e^2)^q mod n
            # 因为 n=pq, hint mod p = e^(2q) mod p
            # 而 e=2^16, 所以 hint mod p = 2^(32q) mod p
            # 由 Fermat: 2^(p-1) ≡ 1 mod p, 所以 2^(32q) = 2^(32q mod (p-1)) mod p
            # 这需要知道 p, 循环依赖
            # 换思路：尝试直接在 sage 中用 nth_root
            # 或者尝试 Pollard rho
            logger.warning("[10733] 无法分解 n，尝试 Pollard rho")
            # 简单 Pollard rho
            def _pollard_rho(n):
                from random import randint
                if n % 2 == 0:
                    return 2
                x = randint(2, n - 1)
                y = x
                c = randint(1, n - 1)
                d = 1
                while d == 1:
                    x = (x * x + c) % n
                    y = (y * y + c) % n
                    y = (y * y + c) % n
                    d = math.gcd(abs(x - y), n)
                return d if d != n else None
            for _ in range(10):
                d = _pollard_rho(n)
                if d and d > 1 and d < n:
                    p_val = d
                    q_val = n // d
                    logger.info("[10733] Pollard rho 分解成功")
                    break
    if not p_val or not q_val:
        return {"error": "n 分解失败（无 p/q/hint 关系不够）",
                "params": {"e": e, "n_bits": n.bit_length(), "has_hint": bool(hint)}}
    # 有 p, q 了，调用 high_exponent skill
    from skills.crypto_high_exponent import run as he_run
    r = he_run({"kind": "auto", "e": e, "p": p_val, "q": q_val, "c": c, "n": n})
    flag = r.get("flag") or r.get("plaintext") or r.get("text")
    if flag:
        return {"flag": flag, "method": "high_exponent_auto", "p": str(p_val)[:20], "q": str(q_val)[:20]}
    return {"flag": None, "method": "he_miss", "detail": r,
            "p": str(p_val)[:20], "q": str(q_val)[:20]}


# ── MISC-01 (10734): bigfile / XOR ──────────────────────────────────

def solve_10734() -> dict:
    """MISC-01: 449MB 嵌套 zip → lime 镜像 → XOR flag。"""
    att = _find_att("10734")
    if not att:
        return {"error": "no attachment"}
    from skills.misc_bigfile_analysis import run as bf_run
    # Step 1: nested_tail 看内层
    r1 = bf_run({"kind": "nested_tail", "path": str(att), "tail_bytes": 50 * 1024 * 1024})
    inner_name = r1.get("inner_entries", [{}])[0].get("name", "") if r1.get("inner_entries") else ""
    logger.info("[10734] inner: %s", inner_name)
    # Step 2: XOR title search（flag^galf 线索）
    r2 = bf_run({"kind": "xor_title_search", "path": str(att), "key": None,
                 "prefixes": ["DASCTF{", "flag{", "ctf{"]})
    if r2.get("hits"):
        for h in r2["hits"][:3]:
            decoded = h.get("decoded", "")
            logger.info("[10734] XOR hit @%s phase=%s: %s", h.get("offset"), h.get("phase"), decoded[:80])
            # 尝试提取 flag
            flags = re.findall(r'DASCTF\{[^}]+\}|flag\{[^}]+\}|ctf\{[^}]+\}', decoded)
            if flags:
                return {"flag": flags[0], "method": "xor_title_search", "offset": h.get("offset")}
    # Step 3: flag_scan 内层
    r3 = bf_run({"kind": "flag_scan", "path": str(att), "chunk_mb": 1,
                 "patterns": ["DASCTF{", "flag{", "ctf{"]})
    if r3.get("hits"):
        for h in r3["hits"][:5]:
            ctx = h.get("context", "")
            flags = re.findall(r'DASCTF\{[^}]+\}|flag\{[^}]+\}|ctf\{[^}]+\}', ctx)
            if flags:
                return {"flag": flags[0], "method": "flag_scan", "offset": h.get("offset")}
    return {"flag": None, "method": "bigfile_miss", "nested": r1.get("inner_entries"), "xor_hits": len(r2.get("hits", []))}


# ── Web REAL flag_scan (10716-10725, 10782-10791, 10794) ───────────

def solve_web_real(cid: str) -> dict:
    """Web REAL: 解压 CMS 源码 → flag_scan 搜索 flag 模式。"""
    att = _find_att(cid)
    if not att:
        return {"error": "no attachment"}
    # 对于 zip/tar.gz，先解压
    tmp = _ROOT / "data" / "tmp_dryrun" / cid
    if not tmp.exists() or not any(tmp.iterdir()):
        if att.suffix == ".zip":
            _unzip_to(att, tmp, max_size=200 * 1024 * 1024)
        elif att.suffix == ".gz":
            import tarfile
            try:
                tmp.mkdir(parents=True, exist_ok=True)
                with tarfile.open(att, "r:gz") as tf:
                    tf.extractall(tmp)
            except Exception as e:
                return {"error": f"tar extract: {e}"}
    if not tmp.exists() or not any(tmp.iterdir()):
        return {"error": "extract failed"}
    # 搜索所有文件中的 flag 模式
    patterns = [rb'DASCTF\{[^}]+\}', rb'flag\{[^}]+\}', rb'ctf\{[^}]+\}']
    hits = []
    for p in tmp.rglob("*"):
        if p.is_file() and p.stat().st_size < 10 * 1024 * 1024:  # skip >10MB
            try:
                data = p.read_bytes()
                for pat in patterns:
                    for m in re.finditer(pat, data):
                        hits.append({"file": str(p.relative_to(tmp)), "match": m.group().decode("latin-1", errors="ignore")})
                        if len(hits) >= 10:
                            break
            except Exception:
                continue
        if len(hits) >= 10:
            break
    if hits:
        return {"flag": hits[0]["match"], "method": "flag_scan", "hits": hits[:5]}
    return {"flag": None, "method": "flag_scan_miss", "files_scanned": sum(1 for _ in tmp.rglob("*") if _.is_file())}


# ── MISC-02 (10735): logbool ────────────────────────────────────────

def solve_10735() -> dict:
    """MISC-02: 附件分析。"""
    att = _find_att("10735")
    if not att:
        return {"error": "no attachment"}
    tmp = _ROOT / "data" / "tmp_dryrun" / "10735"
    if not tmp.exists() or not any(tmp.iterdir()):
        if att.suffix == ".zip":
            _unzip_to(att, tmp)
    # 搜索 flag
    patterns = [rb'DASCTF\{[^}]+\}', rb'flag\{[^}]+\}', rb'ctf\{[^}]+\}']
    for p in tmp.rglob("*"):
        if p.is_file() and p.stat().st_size < 10 * 1024 * 1024:
            try:
                data = p.read_bytes()
                for pat in patterns:
                    for m in re.finditer(pat, data):
                        return {"flag": m.group().decode("latin-1", errors="ignore"),
                                "method": "flag_scan", "file": str(p.name)}
            except Exception:
                continue
    return {"flag": None, "method": "misc_scan_miss", "files": [p.name for p in tmp.rglob("*")][:10]}


# ── 10793: 成功男人背后的女人 ──────────────────────────────────────

def solve_10793() -> dict:
    """misc: 附件分析。"""
    att = _find_att("10793")
    if not att:
        return {"error": "no attachment"}
    tmp = _ROOT / "data" / "tmp_dryrun" / "10793"
    if not tmp.exists() or not any(tmp.iterdir()):
        if att.suffix == ".zip":
            _unzip_to(att, tmp)
    # 搜索 flag
    patterns = [rb'DASCTF\{[^}]+\}', rb'flag\{[^}]+\}', rb'ctf\{[^}]+\}']
    for p in tmp.rglob("*"):
        if p.is_file() and p.stat().st_size < 10 * 1024 * 1024:
            try:
                data = p.read_bytes()
                for pat in patterns:
                    for m in re.finditer(pat, data):
                        return {"flag": m.group().decode("latin-1", errors="ignore"),
                                "method": "flag_scan", "file": str(p.name)}
            except Exception:
                continue
    return {"flag": None, "method": "misc_scan_miss", "files": [p.name for p in tmp.rglob("*")][:10]}


# ── Main ────────────────────────────────────────────────────────────

SOLVERS = {
    "10732": ("crypto", solve_10732),
    "10733": ("crypto", solve_10733),
    "10734": ("misc", solve_10734),
    "10735": ("misc", solve_10735),
    "10793": ("misc", solve_10793),
}

WEB_REAL_IDS = ["10716", "10717", "10718", "10719", "10720", "10722", "10723",
                "10724", "10725", "10782", "10783", "10784", "10785", "10786",
                "10787", "10788", "10789", "10790", "10791", "10794"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", default="", help="逗号分隔题号")
    ap.add_argument("--web", action="store_true", help="跑 web REAL flag_scan")
    args = ap.parse_args()

    results = {}
    ids = []
    if args.ids:
        ids = [x.strip() for x in args.ids.split(",") if x.strip()]
    elif args.web:
        ids = WEB_REAL_IDS
    else:
        ids = list(SOLVERS.keys())

    print(f"\n{'='*60}")
    print(f"直接 Skill 执行桥 — {len(ids)} 题")
    print(f"{'='*60}\n")

    for cid in ids:
        if cid in SOLVERS:
            cat, fn = SOLVERS[cid]
        elif args.web or cid in WEB_REAL_IDS:
            cat, fn = "web", lambda c=cid: solve_web_real(c)
        else:
            print(f"  [{cid}] 无匹配 solver，跳过")
            continue
        print(f"  [{cid}] {cat:8s} ...", end=" ", flush=True)
        try:
            r = fn()
            flag = r.get("flag")
            if flag:
                print(f"✓ {flag[:50]}")
                results[cid] = {"flag": flag, "method": r.get("method", "?"), "category": cat}
            else:
                err = r.get("error") or r.get("method", "unknown")
                print(f"✗ {err}")
                results[cid] = {"flag": None, "error": err, "category": cat, "detail": r}
        except Exception as e:
            print(f"✗ EXC: {e}")
            results[cid] = {"flag": None, "error": str(e), "category": cat}

    # 报表
    solved = sum(1 for r in results.values() if r.get("flag"))
    print(f"\n{'='*60}")
    print(f"  总解出: {solved}/{len(results)}")
    for cid, r in sorted(results.items()):
        flag = r.get("flag")
        cat = r.get("category", "?")
        if flag:
            print(f"    ✓ {cid:6s} {cat:8s} {flag[:50]}")
        else:
            print(f"    ✗ {cid:6s} {cat:8s} {r.get('error', r.get('method', '?'))[:50]}")
    print(f"{'='*60}")

    # 保存
    import time
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = _ROOT / "data" / "results" / f"direct_skill_{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print(f"  结果: {out}")


if __name__ == "__main__":
    main()
