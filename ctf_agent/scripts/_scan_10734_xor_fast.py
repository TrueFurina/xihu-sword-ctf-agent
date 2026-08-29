# -*- coding: utf-8 -*-
"""10734: 高效滞后差扫描（mmap + 限制 L 1..6）"""
import mmap, struct, os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
PATH = os.path.join(_ROOT, "data", "race_extract", "10734", "deep", "ubuntu flag.lime")
P = b"DASCTF{"

def sig_for_l(L):
    return bytes(P[i] ^ P[i + L] for i in range(len(P) - L))

def scan():
    sz = os.path.getsize(PATH)
    with open(PATH, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        for L in range(1, 7):
            sig = sig_for_l(L)
            n = len(sig)
            first = sig[0]
            print(f"L={L} sig={sig.hex()} sz={sz}")
            hits = 0
            pos = 0
            while True:
                pos = m.find(bytes([first]), pos)
                if pos < 0 or pos + n * L >= sz:
                    break
                ok = True
                for k in range(1, n):
                    if m[pos + k * L] != sig[k]:
                        ok = False
                        break
                if ok:
                    hits += 1
                    print(f"  HIT @ {pos:#x} (L={L})")
                    # 现场解码周围 80 字节
                    base = pos - 20
                    raw = m[base:base + 120]
                    for phase in range(L):
                        key = bytearray(L)
                        for i in range(7):
                            key[i % L] = raw[phase + i] ^ P[i]
                        dec = bytes(raw[phase + j] ^ key[j % L] for j in range(0, len(raw) - phase))
                        s = dec.decode('latin-1')
                        if "DASCTF" in s:
                            print(f"    -> PHASE={phase} DECODE: {s[:80]!r}")
                pos += 1
            print(f"  total hits L={L}: {hits}")
        m.close()

if __name__ == "__main__":
    scan()
