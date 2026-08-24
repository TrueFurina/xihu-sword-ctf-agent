# -*- coding: utf-8 -*-
"""10793: Fireworks 私有 chunk 提取分析"""
import glob, zlib

d = r"E:\Program\西湖论剑\ctf_agent\data\tmp_dryrun\10793\out"
fn = glob.glob(d + r"\*.png")[0]
data = open(fn, "rb").read()
i = 8
chunks = []
while i < len(data) - 8:
    ln = int.from_bytes(data[i:i+4], "big")
    typ = data[i+4:i+8]
    payload = data[i+8:i+8+ln]
    if typ in (b"mkBT", b"mkTS", b"mkBF", b"mkBS", b"prVW"):
        chunks.append((typ.decode(), payload))
    i += 12 + ln

print("private chunks:", len(chunks), {t: sum(1 for tt,_ in chunks if tt==t) for t in set(t for t,_ in chunks)})
for t, p in chunks[:6]:
    print(t, len(p), p[:48])

# mkBF 通常是 Fireworks 序列化头(含原始文档元数据)
mkbf = next((p for t, p in chunks if t == "mkBF"), b"")
print("mkBF full head:", mkbf[:300])

# prVW = preview (zlib?)
prvw = next((p for t, p in chunks if t == "prVW"), b"")
try:
    pv = zlib.decompress(prvw)
    print("prVW decompressed:", len(pv), pv[:16])
    open(d + r"\_prvw.bin", "wb").write(pv)
except Exception as ex:
    print("prVW zlib fail:", ex)

# mkTS/mkBT 拼接尝试 zlib（Fireworks 对象数据流）
for name in ("mkTS", "mkBT", "mkBS"):
    blob = b"".join(p for t, p in chunks if t == name)
    print(name, "blob", len(blob), blob[:8])
    try:
        out = zlib.decompressobj().decompress(blob)
        print("  zlib ok:", len(out), out[:40])
        open(d + f"\\_{name}.bin", "wb").write(out)
    except Exception as ex:
        print("  zlib fail:", str(ex)[:80])
