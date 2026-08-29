# -*- coding: utf-8 -*-
"""10793: 渲染 Fireworks mkBT tiles -> PNG + 拼接 contact sheet"""
import glob, zlib, os
from PIL import Image

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
d = os.path.join(_ROOT, "data", "tmp_dryrun", "10793", "out")
fn = glob.glob(os.path.join(d, "*.png"))[0]
data = open(fn, "rb").read()

i = 8
mkbt = []
while i < len(data) - 8:
    ln = int.from_bytes(data[i:i+4], "big")
    typ = data[i+4:i+8]
    if typ == b"mkBT":
        mkbt.append(data[i+8:i+8+ln])
    i += 12 + ln

outdir = os.path.join(d, "tiles")
os.makedirs(outdir, exist_ok=True)
tiles = []
for k, p in enumerate(mkbt):
    off = p.find(b"\x78", 4, 80)
    out = zlib.decompress(p[off:])
    assert len(out) == 65536, (k, len(out))
    im = Image.frombytes("RGBA", (128, 128), out)
    tiles.append(im)
    im.save(os.path.join(outdir, f"tile_{k:02d}.png"))

# contact sheet 15x5
sheet = Image.new("RGBA", (128 * 15, 128 * 5), (255, 255, 255, 255))
for k, im in enumerate(tiles):
    sheet.paste(im, ((k % 15) * 128, (k // 15) * 128))
sheet.save(os.path.join(d, "_sheet.png"))
print("saved", len(tiles), "tiles + sheet")

# 统计每 tile 非透明像素数，找异常
for k, im in enumerate(tiles):
    alpha = im.getchannel("A")
    nz = sum(1 for a in alpha.getdata() if a > 8)
    if nz > 100:
        print(k, "opaque_px", nz)
