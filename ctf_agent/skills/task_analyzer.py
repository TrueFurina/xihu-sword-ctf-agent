"""task_analyzer skill：task.py 算法识别与路由（2026-08-22——疯狂刷题 8% 后补）。

场景：真实题库 33/33 个 task.py 全是 RSA 型加密脚本（Crypto.PublicKey.RSA/
getPrime/PKCS1）。识别：读脚本 → RSA 特征（import/参数）→ 提取 e/n/c →
按 e 特征路由到对应 RSA 解法（真实解出能力）：
- e=3（小指数）→ 小明文开三次方根
- e=65536/2^k（高指数）→ e=2^k 开根（crypto_high_exponent）
- hint=(e*p+e²)^q mod n → hint 解 p（crypto_pkcs1_improved）
- 标准（n 小/费马）→ fermat 分解
"""

import re

RSA_IMPORT_RE = re.compile(
    r"from\s+Crypto\.PublicKey\s+import\s+RSA|Crypto\.PublicKey\.RSA|"
    r"Crypto\.Util\.number|getPrime|PKCS1|import\s+RSA|import\s+\*|gmpy2", re.I
)
E_RE = re.compile(r"\be\s*=\s*(\d+)")
N_RE = re.compile(r"\bn\s*=\s*(\d+)")
HINT_RE = re.compile(r"hint\s*=\s*(\d+)")
FLAG_RE = re.compile(rb"(?:DASCTF|flag|ctf)\{([^}\s]{3,})\}", re.I)


def analyze_script(script: str) -> dict:
    """分析 task.py——识别算法 + 提取参数 + 路由建议。"""
    out = {"algorithm": "unknown", "route": None, "params": {}}
    if not script or not RSA_IMPORT_RE.search(script):
        return out

    out["algorithm"] = "RSA"
    e = E_RE.search(script)
    n = N_RE.search(script)
    hint = HINT_RE.search(script)
    if e:
        out["params"]["e"] = int(e.group(1))
    if n:
        out["params"]["n"] = int(n.group(1))
    if hint:
        out["params"]["hint"] = int(hint.group(1))

    ev = out["params"].get("e", 0)
    if hint:
        out["route"] = "crypto_pkcs1_improved"  # hint 解 p（W/gcd 法）
        out["reason"] = "hint=(e*p+e²)^q mod n 型——解 p 后开根"
    elif ev in (3, 5, 7):  # 小指数
        out["route"] = "small_e_iroot"  # 小明文开 e 次方根
        out["reason"] = f"e={ev} 小指数——小明文直接开根"
    elif ev and ev & (ev - 1) == 0 and ev >= 16:  # 2 的幂（e=65536 等）
        out["route"] = "crypto_high_exponent"  # e=2^k 逐轮开根
        out["reason"] = f"e={ev}=2^k 高指数——逐轮开平方根"
    else:
        out["route"] = "rsa_fermat"  # 标准/费马
        out["reason"] = "标准 RSA——费马分解（n 相邻素数时）"
    out["ok"] = out["algorithm"] in ("RSA",) and out["route"] is not None
    return out


def analyze_file(path: str) -> dict:
    """分析 task.py 文件。"""
    try:
        script = open(path, encoding="utf-8", errors="ignore").read()
        return analyze_script(script)
    except Exception as exc:  # noqa: BLE001
        return {"algorithm": "error", "error": str(exc)}


def run(params: dict) -> dict:
    """skill 统一入口。params: path（task.py 路径）或 script（脚本内容）。"""
    path = params.get("path", "")
    script = params.get("script", "")
    if path:
        r = analyze_file(path)
    else:
        r = analyze_script(script)
    r["ok"] = r.get("algorithm") in ("RSA",) and r.get("route") is not None
    return r


if __name__ == "__main__":
    import glob
    import json
    import os

    # 批量自测：真实 task.py 识别
    files = glob.glob("data/**/task.py", recursive=True)
    ok = 0
    for f in files[:20]:
        r = analyze_file(f)
        if r.get("ok"):
            ok += 1
            print(f"✅ {os.path.basename(os.path.dirname(f))[:25]}: "
                  f"{r['algorithm']} e={r['params'].get('e')} → {r['route']}", flush=True)
    print(f"自测: {ok}/{min(len(files), 20)} 真实 task.py 识别路由成功", flush=True)
