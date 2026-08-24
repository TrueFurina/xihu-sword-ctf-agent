#!/usr/bin/env python3
"""分析 Page 2 的 44 个 drawings"""
import pymupdf as fitz
import os

pdf_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tmp_dryrun', '10732', 'decrypted.pdf')
pdf_path = os.path.normpath(pdf_path)

doc = fitz.open(pdf_path)
page = doc[2]  # Page 2

drawings = page.get_drawings()
print(f'Total drawings: {len(drawings)}')
print(f'Page rect: {page.rect}')
print()

for i, d in enumerate(drawings):
    print(f'--- Drawing {i} ---')
    print(f'  rect: {d.get("rect")}')
    print(f'  type: {d.get("type")}')
    print(f'  fill: {d.get("fill")}')
    print(f'  color: {d.get("color")}')
    print(f'  width: {d.get("width")}')
    # 打印 items
    items = d.get("items", [])
    print(f'  items ({len(items)}):')
    for j, item in enumerate(items):
        print(f'    [{j}] op={item[0]}, ', end='')
        if len(item) > 1:
            # points or rect
            for k in range(1, len(item)):
                val = item[k]
                if hasattr(val, '__iter__'):
                    pts = [f'({p[0]:.1f},{p[1]:.1f})' for p in val] if val else []
                    print(f'pts={pts}', end=' ')
                else:
                    print(f'{val}', end=' ')
        print()
    print()

# 检查 drawings 的 bounding box 范围
all_rects = [d.get("rect") for d in drawings if d.get("rect")]
if all_rects:
    x0 = min(r[0] for r in all_rects)
    y0 = min(r[1] for r in all_rects)
    x1 = max(r[2] for r in all_rects)
    y1 = max(r[3] for r in all_rects)
    print(f'All drawings bounding box: ({x0:.1f}, {y0:.1f}, {x1:.1f}, {y1:.1f})')
    print(f'Page size: {page.rect}')
    print(f'Drawings area: {x1-x0:.1f} x {y1-y0:.1f}')

doc.close()
