"""crypto_pkcs1_padding_oracle skill：PKCS#1 v1.5 低指数攻击与填充解析模板。

真题（西湖论剑 2026-08-21 正式赛 CRYPTO-01 / 10732 "Yusa的密码学课堂——PKCS#1"）攻击链（已实测验证）：
1. hint_enc = pow(hint, e, n)，e=3 且 hint^3 < n → 整数开立方直接恢复 hint
   （hint 文本 "So the message without padding is dangrous. So I improved it"）
2. task.py 打印 KEY.decrypt(AES_KEY_ENC) —— RSA 私钥解密后的 padded AES key，
   255 字节，PKCS#1 v1.5 格式 `00 02 PS 00 msg`
3. 解析填充 → 提取 16 字节 AES key（真题 hex: 44bfc33d0bfb3cd688a074a7adad1504）
4. AES-ECB 解密 PKCS#1.v1.5.enc → 合法 %PDF-1.4（38624 字节，flag 在 PDF 内容层）

kind：
- cuberoot:  c=pow(m,e,n) 且 m^e<n → 低指数整数开方恢复 m（无需 n）
- unpad:     解析 PKCS#1 v1.5（00 02 PS 00 M）→ 提取 M
- aes_ecb:   AES-ECB 解密（key 支持 hex/bytes/base64，PKCS7 自动尝试剥离）
- full:      组合流程（cuberoot → unpad → aes_ecb），一步到位

用法（skill 调用）：
    params = {'kind': 'full', 'c': hint_enc, 'e': 3,
              'padded_hex': '0200...', 'enc_file': 'PKCS#1.v1.5.enc', 'out_file': 'out.pdf'}
"""

import math


def _iroot(n: int, k: int) -> tuple:
    """整数 k 次方根（gmpy2 优先，纯 Python 二分兜底）。返回 (root, exact)。"""
    try:
        import gmpy2
        r, exact = gmpy2.iroot(n, k)
        return int(r), bool(exact)
    except Exception:
        pass
    if n == 0:
        return 0, True
    if n < 0:
        return (-_iroot(-n, k)[0], False) if k % 2 == 0 else (-_iroot(-n, k)[0], False)
    lo, hi = 0, 1
    while hi ** k <= n:
        hi *= 2
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid
    return lo, lo ** k == n


def cuberoot(params: dict) -> dict:
    """低指数整数开方：c = pow(m, e, n) 且 m^e < n → 直接开 e 次方恢复 m。

    n 可省略（关键前提是明文未取模）。真题 e=3 即此场景。
    """
    c = int(params.get("c", 0))
    e = int(params.get("e", 3))
    if c <= 0:
        return {"ok": False, "error": "c 必须为正整数"}
    r, exact = _iroot(c, e)
    res = {"ok": bool(exact), "root": r, "method": f"iroot^{e}", "exact": exact}
    if exact:
        b = r.to_bytes((r.bit_length() + 7) // 8, "big") if r else b""
        res["plaintext"] = b
        res["text"] = b.decode("utf-8", errors="replace")
    else:
        res["note"] = "开方不精确：m^e >= n 已取模，需 Coppersmith 或换攻击路径"
    return res


def pkcs1_v15_unpad(padded: bytes, min_ps: int = 8, msg_len: int = 0) -> dict:
    """解析 PKCS#1 v1.5 填充块：00 02 PS 00 M。

    PS 为至少 8 字节非零随机串；min_ps=0 时放宽（部分题目 PS 很短）。
    返回内层消息 M（hex 一并给出，方便直接当密钥用）。
    容错：pycryptodome long_to_bytes / int.to_bytes 会丢前导 0x00，
    标准块 [00 02 PS 00 M] 经打印/整数往返后常变成 [02 PS 00 M]——
    此时把首字节当 02 处理（start=1），与 [00 02 ...]（start=2）等价。
    篡改兜底（10732 真题）：被篡改的 PKCS1_v1_5.py 把 PS 全填 0x00
    （标准应跳过零字节，篡改版只保留零字节）→ 块变成 00 02 [全零] M，
    标准「首个 0x00 即分隔符」会误判 PS 长度=0。此时传 msg_len 走尾部提取：
    msg = padded[-msg_len:]（M 紧贴块尾，前导全零 PS 无影响）。
    """
    if not padded or len(padded) < 3:
        return {"ok": False, "error": "填充块过短"}
    if padded[0] == 0x00 and len(padded) >= 2 and padded[1] == 0x02:
        start = 2
    elif padded[0] == 0x02:
        start = 1  # 前导 00 被 long_to_bytes 丢弃
    else:
        return {"ok": False, "error": "不是 PKCS#1 v1.5 块（须以 00 02 或 02 开头）"}
    sep = padded.find(b"\x00", start)
    if sep < 0:
        return {"ok": False, "error": "未找到 00 分隔符"}
    ps_len = sep - start
    # 篡改兜底：PS 全零导致 sep==start（ps_len=0）→ 走尾部提取
    if ps_len < min_ps:
        if msg_len and len(padded) >= msg_len:
            msg = padded[-msg_len:]
            return {
                "ok": True,
                "msg": msg,
                "msg_hex": msg.hex(),
                "ps_len": ps_len,
                "block_len": len(padded),
                "msg_len": len(msg),
                "method": "tail-extract",
                "note": "PS 长度异常（疑似篡改的 PKCS1_v1_5：PS 全填 0x00），按 msg_len 尾部提取",
            }
        return {"ok": False,
                "error": f"PS 长度 {ps_len} < {min_ps}（疑似篡改全零 PS：传 msg_len 走尾部提取，或 min_ps=0）",
                "ps_len": ps_len}
    msg = padded[sep + 1:]
    return {
        "ok": True,
        "msg": msg,
        "msg_hex": msg.hex(),
        "ps_len": ps_len,
        "block_len": len(padded),
        "msg_len": len(msg),
        "method": "standard",
    }


def _long_to_padded(val: int, key_bytes: int = 0) -> bytes:
    """整数 → bytes；key_bytes>0 时左填 0x00 到固定长度（RSA 块长）。"""
    if val == 0:
        return b"\x00"
    b = val.to_bytes((val.bit_length() + 7) // 8, "big")
    if key_bytes and len(b) < key_bytes:
        b = b"\x00" * (key_bytes - len(b)) + b
    return b


def _load_key(key) -> bytes:
    """key 支持：bytes / hex 字符串 / base64 字符串 / 普通文本。"""
    if isinstance(key, bytes):
        return key
    s = str(key).strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    try:
        return bytes.fromhex(s)
    except ValueError:
        pass
    try:
        import base64
        b = base64.b64decode(s, validate=True)
        return b
    except Exception:
        return s.encode("utf-8")


def aes_ecb_decrypt(params: dict) -> dict:
    """AES-ECB 解密。key 必填；密文取 enc_file 路径或 data bytes。"""
    from Crypto.Cipher import AES
    key = _load_key(params.get("key", ""))
    if not key:
        return {"ok": False, "error": "缺少 key"}
    data = params.get("data", b"")
    path = params.get("enc_file") or (params.get("data") if isinstance(params.get("data"), str) else None)
    if path:
        with open(path, "rb") as f:
            data = f.read()
    if not data:
        return {"ok": False, "error": "缺少密文（enc_file 或 data）"}
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(data)
    # PKCS7 剥离尝试
    pad = pt[-1] if pt else 0
    if pt and 0 < pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt_u = pt[:-pad]
        unpadded = True
    else:
        pt_u, unpadded = pt, False
    out_file = params.get("out_file")
    if out_file:
        with open(out_file, "wb") as f:
            f.write(pt_u)
    res = {
        "ok": True,
        "plaintext": pt_u,
        "padded_removed": unpadded,
        "size": len(pt_u),
        "out_file": out_file,
    }
    # 嗅探文件类型（PDF/文本等）
    if pt_u[:5] == b"%PDF-":
        res["file_type"] = "PDF"
    elif pt_u[:2] in (b"PK",):
        res["file_type"] = "ZIP"
    elif pt_u[:4] in (b"\x89PNG", b"GIF8", b"\xff\xd8\xff"):
        res["file_type"] = "IMAGE"
    return res


def full(params: dict) -> dict:
    """组合流程：cuberoot 恢复 hint → unpad 提取 AES key → AES-ECB 解密文件。"""
    steps = {}
    if params.get("c"):
        steps["cuberoot"] = cuberoot(params)
        if steps["cuberoot"].get("ok") and not params.get("key"):
            # 开方结果若是 PKCS#1 填充块，自动进 unpad
            pt = steps["cuberoot"].get("plaintext")
            if pt and (pt[:2] == b"\x00\x02" or pt[:1] == b"\x02"):
                params["padded"] = pt
    # 支持 padded_long（整数，常见：task.py 直接打印 RSA 解密值）
    if params.get("padded_long") is not None:
        params["padded"] = _long_to_padded(int(params["padded_long"]),
                                          int(params.get("key_bytes", 0) or 0))
    if params.get("padded_hex") or params.get("padded") is not None:
        if params.get("padded_hex"):
            padded = bytes.fromhex(str(params["padded_hex"]).replace("0x", ""))
        else:
            padded = params["padded"]
        if isinstance(padded, str):
            padded = bytes.fromhex(padded.replace("0x", ""))
        steps["unpad"] = pkcs1_v15_unpad(padded, min_ps=int(params.get("min_ps", 8)),
                                          msg_len=int(params.get("msg_len", 0) or 0))
        if steps["unpad"].get("ok") and not params.get("key"):
            params["key"] = steps["unpad"]["msg"]
    if params.get("enc_file") and params.get("key"):
        steps["aes_ecb"] = aes_ecb_decrypt(params)
    ok = all(v.get("ok") for v in steps.values())
    return {"ok": ok, "steps": steps}


def crypto_pkcs1_padding_oracle(params: dict) -> dict:
    """skill 入口。"""
    kind = params.get("kind", "full")
    if kind == "cuberoot":
        return cuberoot(params)
    if kind == "unpad":
        if params.get("padded_long") is not None:
            padded = _long_to_padded(int(params["padded_long"]),
                                     int(params.get("key_bytes", 0) or 0))
        elif params.get("padded_hex"):
            padded = bytes.fromhex(str(params["padded_hex"]).replace("0x", ""))
        else:
            padded = params.get("padded", b"")
        if isinstance(padded, str):
            padded = bytes.fromhex(padded.replace("0x", ""))
        return pkcs1_v15_unpad(padded, min_ps=int(params.get("min_ps", 8)),
                               msg_len=int(params.get("msg_len", 0) or 0))
    if kind == "aes_ecb":
        return aes_ecb_decrypt(params)
    if kind == "full":
        return full(params)
    return {"ok": False, "error": f"unknown kind: {kind}"}


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return crypto_pkcs1_padding_oracle(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="PKCS#1 v1.5 低指数攻击与填充解析")
    parser.add_argument("--kind", default="full",
                        choices=["cuberoot", "unpad", "aes_ecb", "full"])
    parser.add_argument("--c", type=int, default=0)
    parser.add_argument("--e", type=int, default=3)
    parser.add_argument("--padded-hex", default="")
    parser.add_argument("--key", default="")
    parser.add_argument("--enc-file", default="")
    parser.add_argument("--out-file", default="")
    args = parser.parse_args()
    import json

    params = {"kind": args.kind, "c": args.c, "e": args.e}
    if args.padded_hex:
        params["padded_hex"] = args.padded_hex
    if args.key:
        params["key"] = args.key
    if args.enc_file:
        params["enc_file"] = args.enc_file
    if args.out_file:
        params["out_file"] = args.out_file
    print(json.dumps(crypto_pkcs1_padding_oracle(params), ensure_ascii=False, indent=1,
                     default=lambda o: o.decode("latin-1") if isinstance(o, bytes) else str(o)))


if __name__ == "__main__":
    main()
