"""ZipCrypto 已知明文攻击 (KPA)——免密破解 zip 加密 (Z3 版)。

原理 (对照 CPython zipfile._ZipDecrypter):
  ZipCrypto 每个条目从密码重新初始化 K0/K1/K2, 生成 12B 头部后加密数据。
  keystream 单步:
      k  = k2 | 2
      ks = ((k * (k ^ 1)) >> 8) & 0xff          # keystream 字节
      k0 = crc32(k0, p)                          # p = 明文 (解密时已知明文)
      k1 = ((k1 + (k0 & 0xff)) * 134775813 + 1) & 0xffffffff
      k2 = crc32(k2, (k1 >> 24) & 0xff)

已知明文攻击: 若同 zip 某条目明文已知 (压缩后字节), 数据段 keystream = 密文 ^ 明文
已知 17 个连续 keystream 字节 → Z3 解出数据段起始 (K0,K1,K2) → 免密解密其他条目。

用法:
  python scripts/_kpa_zip.py   # 内置玄盾杯 xuanhun_ezip 层2 场景
"""
import binascii
import struct
import sys
import zlib

from z3 import BitVec, BitVecVal, Extract, If, LShR, Solver, sat

M32 = BitVecVal(0xFFFFFFFF, 32)


def _crc_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        table.append(c)
    return table


_CRC_TABLE = _crc_table()


def _crc32_affine():
    """crc32(crc, byte) 在 GF(2) 上是仿射函数: 40 输入位 → 32 输出位。
    contribs[k] = 第 k 输入位=1 (其余 0) 时的输出; base = 全 0 输入输出。
    crc32 = base ⊕ (所有置位输入位的 contrib)。
    输入位序: 0..31 = crc 位, 32..39 = byte 位。"""
    contribs = [0] * 40
    for k in range(40):
        c = (1 << k) if k < 32 else 0
        b = (1 << (k - 32)) if k >= 32 else 0
        contribs[k] = _CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    base = _CRC_TABLE[0]
    return contribs, base


_CRC_CONTRIBS, _CRC_BASE = _crc32_affine()


def _crc32_int(crc: int, b: int) -> int:
    """原始 crc32 单字节更新 (无最终异或, 与 ZipCrypto 一致)"""
    return _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)


def _crc32_z3(crc, byte):
    """仿射编码 crc32 (Z3 线性, 40 个 If 替代 256 层数组 Select)"""
    out = BitVecVal(_CRC_BASE, 32)
    for k in range(32):
        out = If(Extract(k, k, crc) == 1,
                 out ^ BitVecVal(_CRC_CONTRIBS[k], 32), out)
    for k in range(8):
        out = If(Extract(k, k, byte) == 1,
                 out ^ BitVecVal(_CRC_CONTRIBS[32 + k], 32), out)
    return out


def _extract_entry(raw: bytes, fname: str):
    """从 zip 二进制提取条目局部头信息: (密文, method, csize, usize, crc)"""
    idx = raw.find(fname.encode())
    if idx < 0:
        raise ValueError(f"{fname} not in zip binary")
    lh = idx - 30
    (sig, ver, flags, method, modt, modd, crc, csize, usize,
     nlen, xlen) = struct.unpack_from("<IHHHHHIIIHH", raw, lh)
    if sig != 0x04034B50:
        raise ValueError(f"bad local header sig for {fname}")
    ds = lh + 30 + nlen + xlen
    return raw[ds:ds + csize], method, csize, usize, crc, flags


def solve_data_state(ks_known: list, plain_known: bytes):
    """已知数据段 keystream 字节列表 + 对应明文, 解出数据段起始 (K0,K1,K2)。
    返回 (k0, k1, k2) 或 None。
    优化: keystream 只依赖 key2 低 16 位 (已验证等价), 用 16 位乘法缩小 bit-blast。
    """
    s = Solver()
    s.set("timeout", 90000)  # 90s 上限, 避免无限求解
    k0 = BitVec("k0", 32)
    k1 = BitVec("k1", 32)
    k2 = BitVec("k2", 32)
    for kb, pb in zip(ks_known, plain_known):
        k16 = Extract(15, 0, k2) | BitVecVal(2, 16)
        t16 = k16 * (k16 ^ BitVecVal(1, 16))
        ks = Extract(15, 8, t16)  # 16 位乘法取位 8-15 == 32 位乘法结果
        s.add(ks == kb)
        # 密钥更新用明文
        p = BitVecVal(pb, 32)
        k0n = _crc32_z3(k0, p)
        k1n = ((k1 + (k0n & 0xFF)) * BitVecVal(134775813, 32) + 1) & M32
        k2n = _crc32_z3(k2, LShR(k1n, 24) & 0xFF)
        k0, k1, k2 = k0n, k1n, k2n
    if s.check() != sat:
        return None
    m = s.model()
    return tuple(int(m.eval(v, model_completion=True)) for v in (k0, k1, k2))


def decrypt_with_state(cipher: bytes, k0: int, k1: int, k2: int) -> bytes:
    """用数据段起始状态解密条目数据段"""
    out = bytearray()
    for c in cipher:
        k = k2 | 2
        ks = ((k * (k ^ 1)) >> 8) & 0xFF
        p = c ^ ks
        out.append(p)
        k0 = _crc32_int(k0, p)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_int(k2, (k1 >> 24) & 0xFF)
    return bytes(out)


def init_keys(pw: bytes):
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for b in pw:
        k0 = _crc32_int(k0, b)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_int(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2


def gen_keystream(k0, k1, k2, n):
    ks = bytearray()
    for _ in range(n):
        k = k2 | 2
        ks.append(((k * (k ^ 1)) >> 8) & 0xFF)
        # keystream 生成时密钥更新用 keystream 自身 (加密头场景)
        p = ks[-1]
        k0 = _crc32_int(k0, p)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_int(k2, (k1 >> 24) & 0xFF)
    return bytes(ks)


def main():
    ZDIR = r"E:/Program/Cybersecurity/比赛真题/2020年玄盾杯试题(1)/Misc_EZIP"
    import zipfile
    from zipfile import _ZipDecrypter

    zf1 = zipfile.ZipFile(ZDIR + "/multzip1.zip")
    raw1 = open(ZDIR + "/multzip1.zip", "rb").read()
    l2 = zf1.read("multzip2.zip", pwd=b"66688")

    # ---- 0) 基准验证: 层1 (密码 66688 已知) ----
    c1, m1, s1, u1, crc1, f1 = _extract_entry(raw1, "Readme.txt")
    plain1 = _ZipDecrypter(b"66688")(c1)      # 29B 明文 (含12B头部)
    p1_data = plain1[12:]                      # 17B 压缩数据
    k0h, k1h, k2h = init_keys(b"66688")
    # 头部12B: 密钥更新用 keystream; 数据段: 更新用明文
    k0, k1, k2 = k0h, k1h, k2h
    for cb in c1[:12]:  # 头部12B: 用解密后的头部字节更新密钥
        k = k2 | 2
        ks = ((k * (k ^ 1)) >> 8) & 0xFF
        hp = cb ^ ks  # 头部明文
        k0 = _crc32_int(k0, hp)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_int(k2, (k1 >> 24) & 0xFF)
    st_data = (k0, k1, k2)                     # 数据段起始状态
    ks_data = bytearray()
    k0, k1, k2 = st_data
    for pb in p1_data:
        k = k2 | 2
        ks_data.append(((k * (k ^ 1)) >> 8) & 0xFF)
        k0 = _crc32_int(k0, pb)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc32_int(k2, (k1 >> 24) & 0xFF)
    print(f"[0] 基准: 层1 数据段起始状态 = ({st_data[0]:08x},{st_data[1]:08x},{st_data[2]:08x})")
    print(f"    层1 数据段 keystream = {bytes(ks_data).hex()}")

    # 模型自测: 用 keystream+明文 解状态
    got = solve_data_state(list(ks_data), p1_data)
    if got is None:
        print("[0] ❌ 基准模型 UNSAT——模型仍有 bug")
        return 1
    print(f"[0] Z3 解出 = ({got[0]:08x},{got[1]:08x},{got[2]:08x}) "
          f"{'✅ 与真值一致' if got == st_data else '❌ 不一致!'}")

    # ---- 1) 层2 KPA ----
    c2, m2, s2, u2, crc2, f2 = _extract_entry(l2, "Readme.txt")
    header2, cdata2 = c2[:12], c2[12:]
    print(f"\n[1] 层2 Readme.txt: 密文{len(c2)}B CRC={crc2:08x}")

    # 关键假设: 层2 Readme.txt 压缩字节 == 层1 (CRC 一致 + 同工具同内容)
    ks_known = [a ^ b for a, b in zip(cdata2, p1_data)]
    st2 = solve_data_state(ks_known, p1_data)
    if st2 is None:
        print("[1] ❌ 假设失败: 层2 压缩字节 != 层1 (Z3 UNSAT)")
        return 1
    print(f"[1] ✅ 层2 数据段起始状态 = ({st2[0]:08x},{st2[1]:08x},{st2[2]:08x})")

    # ---- 2) 免密解密 multzip3.zip ----
    c3, m3, s3, u3, crc3_, f3 = _extract_entry(l2, "multzip3.zip")
    print(f"[2] multzip3.zip: method={m3} 密文{len(c3)}B = 头12 + 数据{len(c3)-12}B CRC={crc3_:08x}")
    plain3 = decrypt_with_state(c3[12:], *st2)
    ok = (binascii.crc32(plain3) & 0xFFFFFFFF) == crc3_
    print(f"[2] 解密: 前4B={plain3[:4]!r} CRC={binascii.crc32(plain3) & 0xFFFFFFFF:08x} "
          f"期望={crc3_:08x} {'✅' if ok else '❌'}")
    if not ok:
        return 1
    out = ZDIR + "/layer3_decrypted.zip"
    with open(out, "wb") as fp:
        fp.write(plain3)
    print(f"[2] 已写出 {out} ({len(plain3)}B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
