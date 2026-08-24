"""本地可复现 benchmark（2026-08-24——P1 工程能力交付②）

用途：题库 → 自动解出 → 统计解出数/耗时/失败归因 → JSON 留档。
诚实口径：所有解出为「离线推导（未平台验证——accepted=0）」。

用法：
    python scripts/_local_benchmark.py [题库目录]
输出：benchmark_report.json（解出数/耗时/失败归因——可复现）

实现：确定性解出器（模板/解出链 skill——无 LLM——可复现）：
- plain 明文 flag 提取（flag{...} 正则）
- caesar/ROT13 解码（26 位移遍历——flag{ 命中）
- base64/hex 解码（可读 flag）
"""

import glob, os, re, json, time, base64, sys

FLAG_RE = re.compile(rb'(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}', re.I)


def _try_plain(content: bytes):
    for m in FLAG_RE.finditer(content):
        return b'flag{' + m.group(1) + b'}'
    return None


def _try_caesar_rot13(content: bytes):
    text = content.decode('utf-8', errors='ignore')
    for shift in range(26):
        out = ''.join(
            chr((ord(c) - 97 + shift) % 26 + 97) if 'a' <= c <= 'z' else
            chr((ord(c) - 65 + shift) % 26 + 65) if 'A' <= c <= 'Z' else c
            for c in text)
        if 'flag{' in out.lower() or 'dasctf{' in out.lower():
            m = re.search(r'(?:DASCTF|flag|ctf)\{[^}\s]{3,}', out)
            if m:
                return m.group(0).encode()
    t = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                      'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
    out13 = text.translate(t)
    m = re.search(r'(?:DASCTF|flag|ctf)\{[^}\s]{3,}', out13)
    if m:
        return m.group(0).encode()
    return None


def _try_b64_hex(content: bytes):
    text = content.decode('utf-8', errors='ignore').strip()
    if len(text) < 8 or not re.fullmatch(r'[A-Za-z0-9+/=]+', text):
        return None
    try:
        dec = base64.b64decode(text)
        if FLAG_RE.search(dec):
            return FLAG_RE.search(dec).group(0)
    except Exception:
        pass
    try:
        dec = bytes.fromhex(text)
        if FLAG_RE.search(dec):
            return FLAG_RE.search(dec).group(0)
    except Exception:
        pass
    return None


SOLVERS = [("plain", _try_plain), ("caesar/rot13", _try_caesar_rot13),
           ("b64/hex", _try_b64_hex)]


def solve_one(path: str) -> tuple:
    try:
        content = open(path, 'rb').read()
    except Exception:
        return None, "read_error"
    if len(content) > 1_000_000:
        return None, "too_large"
    for name, solver in SOLVERS:
        try:
            r = solver(content)
            if r:
                return r, name
        except Exception:
            continue
    return None, "unsolved"


def run(root: str = "data/attachments") -> dict:
    files = []
    for pat in ("**/*.txt", "**/*.log", "**/*.json", "**/*.out"):
        files.extend(glob.glob(os.path.join(root, pat), recursive=True))
    files = [f for f in files if os.path.getsize(f) < 1_000_000]
    results = []
    t0 = time.time()
    for f in sorted(files):
        s = time.time()
        flag, solver = solve_one(f)
        results.append({
            "file": os.path.basename(f),
            "solved": flag is not None,
            "flag": flag.decode('utf-8', errors='ignore') if flag else None,
            "solver": solver,
            "time_s": round(time.time() - s, 3),
        })
    total = time.time() - t0
    solved = [r for r in results if r["solved"]]
    report = {
        "_honest_note": "离线推导（未平台验证——accepted=0）——本地可复现 benchmark",
        "date": "2026-08-24",
        "题库": root,
        "文件数": len(results),
        "解出数": len(solved),
        "解出率": round(len(solved) / max(len(results), 1), 3),
        "总耗时_s": round(total, 2),
        "均单题_s": round(total / max(len(results), 1), 3),
        "solver分布": {},
        "解出列表": [{"file": r["file"], "flag": r["flag"], "solver": r["solver"]}
                  for r in solved],
        "失败归因": {},
    }
    for r in results:
        report["solver分布"][r["solver"]] = report["solver分布"].get(r["solver"], 0) + 1
    for r in results:
        if not r["solved"]:
            report["失败归因"][r["solver"]] = report["失败归因"].get(r["solver"], 0) + 1
    out = "benchmark_report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("解出列表",)}, ensure_ascii=False, indent=2))
    return report


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "data/attachments"
    run(root)
