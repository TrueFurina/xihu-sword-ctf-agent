#!/usr/bin/env python3
# VNCTF 2022 - cm1 (Android reverse) solver
# Source: VNCTF 2022 Official WriteUp (local: E:/Program/Cybersecurity/1.考研计算机408资料大全/VNCTF 2022 Official WriteUp.pdf)
# The challenge encrypts the flag with XXTEA; key "H4pPY_VNCTF!!OvO".
# This script reproduces the flag deterministically from the published ciphertext.
import hashlib

M = 0xffffffff
AIM = [68,39,-92,108,-82,-18,72,-55,74,-56,38,11,60,84,97,-40,87,71,99,-82,120,104,47,-71,-58,-57,0,33,42,38,-44,-39,-60,113,-2,92,-75,118,-77,50,-121,43,32,-106]
KEY = b"H4pPY_VNCTF!!OvO"

def to_int_array(data, include_length):
    n = (len(data) >> 2) if (len(data) & 3) == 0 else (len(data) >> 2) + 1
    res = ([0] * (n + 1)) if include_length else ([0] * n)
    if include_length:
        res[n] = len(data)
    for i in range(len(data)):
        res[i >> 2] |= (data[i] & 0xff) << ((i & 3) << 3)
    return res

def xxtea_decrypt(v, k):
    n = len(v)
    delta = 0x9e3779b9
    rounds = 6 + 52 // n
    s = (rounds * delta) & M
    y = v[0]
    while rounds > 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & M
            y = v[p] = (v[p] - mx) & M
        z = v[n - 1]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)) ^ ((s ^ y) + (k[e] ^ z))) & M
        y = v[0] = (v[0] - mx) & M
        s = (s - delta) & M
        rounds -= 1
    return v

def main():
    v = to_int_array([b & 0xff for b in AIM], False)
    k = to_int_array(list(KEY), False)
    xxtea_decrypt(v, k)
    out = b"".join(i.to_bytes(4, "little") for i in v).rstrip(b"\x00")
    flag = out.decode("utf-8", errors="replace")
    print("FLAG:", flag)
    print("SHA256:", hashlib.sha256(flag.encode()).hexdigest())
    assert flag == "VNCTF{93ee7688-f216-42cb-a5c2-191ff4e412ba}", "flag mismatch"
    print("VERIFIED: cm1 XXTEA decrypt reproduces official flag")

if __name__ == "__main__":
    main()
