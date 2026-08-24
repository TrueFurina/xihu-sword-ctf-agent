"""crypto_ecb_block_attack skill：AES-ECB 块攻击（ECB 块独立性利用）。

场景（crypto-004 黑盒 oracle 题）：加密服务用 AES-ECB，相同明文块产生相同密文块。
攻击方式：
1. byte-at-a-time ECB：把未知明文（flag）拼在可控输入后加密，
   通过调整填充对齐块边界，逐字节推出未知明文
2. 块重复检测：注入长重复块 → 密文中出现重复块 = ECB 特征确认

用法（skill 调用）：
    params = {'encrypt_oracle': fn(可控输入 bytes) -> 密文 bytes, 'prefix_len': flag前前缀长度}
    result = crypto_ecb_block_attack(params) -> {'ok': True, 'plaintext': flag}
"""


def ecb_detect_block_size(oracle) -> int:
    """探测块大小：输入长度递增，密文长度第一次跳跃点之差 = 块大小。"""
    base = len(oracle(b""))
    for n in range(1, 64):
        if len(oracle(b"A" * n)) != base:
            return len(oracle(b"A" * n)) - base
    return 16  # 默认 AES 块 16


def ecb_detect_mode(oracle, block_size: int = 16) -> bool:
    """检测是否 ECB：注入 3 个相同块，密文出现重复块即 ECB。"""
    payload = b"A" * (block_size * 3)
    ct = oracle(payload)
    blocks = [ct[i:i + block_size] for i in range(0, len(ct) - block_size + 1, block_size)]
    return len(blocks) != len(set(blocks))


def byte_at_a_time_ecb(oracle, prefix_len: int = 0, block_size: int = 16,
                       max_len: int = 128) -> str:
    """byte-at-a-time ECB：逐字节恢复未知明文（flag）。

    oracle: fn(可控输入) -> 密文（内部结构 = prefix + 可控输入 + 未知明文 + padding）
    prefix_len: 未知明文前的前缀长度（如 "flag{...}" 前的已知内容）

    原理：oracle(filler) 与 oracle(filler + unknown + c) 中，未知明文起始偏移相同
    （都是 prefix_len + len(filler)），因此未知明文第 i 字节所在块在两个输出中
    位置一致——构造同 filler 比较目标块，逐字节恢复。
    """
    unknown = b""
    for i in range(max_len):
        # 填充使未知明文第 i 字节落在块内最后一字节（块尾）
        pad = (block_size - 1 - (prefix_len + i) % block_size) % block_size
        filler = b"A" * pad
        base_ct = oracle(filler)
        # 目标块起始：flag[i] 在块尾 → 块起始 = flag[i]偏移 - (block_size-1)
        block_start = prefix_len + pad + i - (block_size - 1)
        target_block = base_ct[block_start:block_start + block_size]
        found = None
        for c in range(32, 127):
            # test = filler + 已恢复前缀 + c，c 恰好落在 flag[i] 位置（块尾，同 block_start）
            test = filler + unknown + bytes([c])
            ct = oracle(test)
            cand_block = ct[block_start:block_start + block_size]
            if cand_block == target_block:
                found = c
                break
        if found is None:
            break  # 无法恢复更多（可能已到明文末尾）
        unknown += bytes([found])
        if found == 125:  # '}' flag 结束
            break
    return unknown.decode("utf-8", errors="replace")


def crypto_ecb_block_attack(params: dict) -> dict:
    """skill 入口。"""
    oracle = params.get("encrypt_oracle")
    if oracle is None:
        return {"ok": False, "error": "缺少 encrypt_oracle（加密函数）"}
    block_size = params.get("block_size", 0) or ecb_detect_block_size(oracle)
    is_ecb = ecb_detect_mode(oracle, block_size)
    if not is_ecb:
        return {"ok": False, "note": f"检测到非 ECB（块大小 {block_size}）——相同块未产生相同密文，换 CBC/其他攻击"}
    prefix_len = int(params.get("prefix_len", 0))
    plain = byte_at_a_time_ecb(oracle, prefix_len=prefix_len, block_size=block_size,
                               max_len=int(params.get("max_len", 128)))
    return {"ok": True, "block_size": block_size, "is_ecb": True, "plaintext": plain}


def run(params: dict) -> dict:
    """SkillManager 统一入口。"""
    return crypto_ecb_block_attack(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="AES-ECB 块攻击")
    parser.add_argument("--demo", action="store_true", help="自演示（mock ECB oracle）")
    args = parser.parse_args()

    if args.demo:
        import os

        from Crypto.Cipher import AES

        key = os.urandom(16)
        flag = b"flag{ECB_block_attack_2026_demo}"

        def oracle(data: bytes) -> bytes:
            plain = b"prefix:" + data + flag
            pad = 16 - (len(plain) % 16)  # PKCS7 padding 到块边界
            plain += bytes([pad]) * pad
            return AES.new(key, AES.MODE_ECB).encrypt(plain)

        import json

        print(json.dumps(crypto_ecb_block_attack(
            {"encrypt_oracle": oracle, "prefix_len": len(b"prefix:")}
        ), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
