# -*- coding: utf-8 -*-
"""10734 MISC-01 flag^galf: lime 内存 XOR 编码 flag 定位
滞后差不变式：重复密钥(长L) XOR 下 T[i]^T[i+L] = P[i]^P[i+L]，与密钥内容/相位无关。
对每个 L 扫 "DASCTF{" 的 lag-L 签名，命中后现场爆破密钥并输出解码结果。
"""
import sys

PATH = r"E:\Program\西湖论剑\ctf_agent\data\race_extract\10734\deep\ubuntu flag.lime"
P = b"DASCTF{"
CHUNK = 64 << 20

def scan():
    hits = []
    with open(PATH, "rb") as f:
        off = 0
        prev_tail = b""
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            data = prev_tail + buf
            base = off - len(prev_tail)
            for L in range(1, 7):
                # lag-L 签名: s[i] = P[i]^P[i+L], 出现在 pos i, i+L, i+2L...
                sigs = [(i, P[i] ^ P[i + L]) for i in range(len(P) - L)]
                n = len(sigs)
                if n < 2:
                    continue
                start0 = sigs[0][0]
                stride = L
                # 扫描每个可能的锚点 j: data[j]==sigs[0], data[j+L]==sigs[1], ...
                first = sigs[0][1]
                j = 0
                while True:
                    j = data.find(bytes([first]), j)
                    if j < 0 or j + (n - 1) * L + L >= len(data):
                        break
                    ok = True
                    for k in range(1, n):
                        if data[j + k * L] != sigs[k][1]:
                            ok = False
                            break
                    if ok:
                        pos = base + j - start0  # P[0] 在文件中的位置
                        hits.append((L, pos))
                        print(f"[HIT] L={L} flag_start_offset={pos:#x}")
                        # 现场恢复: 取 T[pos:pos+7+L], 爆破/推导密钥
                        seg = data[max(0, j - start0): j - start0 + 7 + 40]
                        for ph in range(L):
                            key = bytes(seg[ph + i] ^ P[i if ph + i < 7 else 0] if ph + i < 7 else 0 for i in range(0))
                            # 直接按相位推导密钥字节
                        # 密钥字节 = T[ph + i*L] ^ P[ph + i*L] (对齐到 P 内)
                        key = bytearray(L)
                        for i in range(7):
                            key[i % L] = seg[i] ^ P[i]
                        # 用推导密钥解码后续 64 字节（前缀已消费 7）
                        dec = bytes(seg[7 + i] ^ key[(7 + i) % L] for i in range(min(60, len(seg) - 7)))
                        print(f"      key~{bytes(key)!r} decode_after_prefix={dec[:48]!r}")
                    j += 1
            prev_tail = data[-(len(P) + 8):]
            off += len(buf)
    print("total hits:", len(hits))
    return hits

if __name__ == "__main__":
    scan()
