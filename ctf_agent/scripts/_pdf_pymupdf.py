#!/usr/bin/env python3
"""用 PyMuPDF 深度提取 10732 PDF 内容"""
import pymupdf as fitz  # PyMuPDF
import re, os

pdf_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tmp_dryrun', '10732', 'decrypted.pdf')
pdf_path = os.path.normpath(pdf_path)

doc = fitz.open(pdf_path)
print(f'Pages: {doc.page_count}')
print(f'Metadata: {doc.metadata}')
print()

for page_num in range(doc.page_count):
    page = doc[page_num]
    print(f'\n{"="*60}')
    print(f'=== Page {page_num} ===')
    print(f'Page rect: {page.rect}')

    # 1. 提取文本（带格式）
    text = page.get_text("text")
    print(f'\nText ({len(text)} chars):')
    print(repr(text))

    # 2. 提取文本块（带位置）
    blocks = page.get_text("dict")["blocks"]
    print(f'\nBlocks: {len(blocks)}')
    for i, block in enumerate(blocks):
        if block["type"] == 0:  # text block
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text_val = span.get("text", "").strip()
                    if text_val:
                        print(f'  Span: pos={span["bbox"]}, font={span["font"]}, size={span["size"]:.1f}, color={span["color"]:#x}, text={repr(text_val)}')
                        # 检查白色文本或超小字体
                        if span["color"] == 0xFFFFFF or span["size"] < 3:
                            print(f'  *** SUSPICIOUS: color={span["color"]:#x}, size={span["size"]:.1f} ***')
        elif block["type"] == 1:  # image block
            print(f'  IMAGE block: {block["bbox"]}, width={block.get("width")}, height={block.get("height")}')

    # 3. 检查链接
    links = page.get_links()
    if links:
        print(f'\nLinks: {links}')

    # 4. 检查注释
    annots = list(page.annots()) if page.annots() else []
    if annots:
        print(f'\nAnnotations: {len(annots)}')
        for annot in annots:
            print(f'  {annot}')

    # 5. 提取图片
    images = page.get_images(full=True)
    if images:
        print(f'\nImages: {len(images)}')
        for img in images:
            print(f'  {img}')

    # 6. 提取 drawings (vector graphics)
    drawings = page.get_drawings()
    if drawings:
        print(f'\nDrawings: {len(drawings)}')

# 7. 检查 PDF 附件/嵌入式文件
print(f'\n{"="*60}')
print(f'Embedded files: {doc.embfile_count()}')
for i in range(doc.embfile_count()):
    info = doc.embfile_info(i)
    print(f'  {info}')

# 8. 检查 PDF 注释
print(f'\nPDF annotations:')
for page in doc:
    for annot in page.annots():
        print(f'  Page {page.number}: {annot.type}, {annot.info}')

# 9. 渲染每页为图片（用于 OCR/视觉检查）
print(f'\nRendering pages as images...')
for page_num in range(doc.page_count):
    page = doc[page_num]
    pix = page.get_pixmap(dpi=300)
    img_path = os.path.join(os.path.dirname(pdf_path), f'page_{page_num}.png')
    pix.save(img_path)
    print(f'  Page {page_num} saved to {img_path} ({pix.width}x{pix.height})')

# 10. 搜索 DASCTF/flag/ctf in all text
print(f'\n{"="*60}')
print('Searching for flag patterns in all pages...')
for page_num in range(doc.page_count):
    page = doc[page_num]
    for pattern in ['DASCTF', 'flag{', 'ctf{', 'FLAG{', 'dasctf']:
        rects = page.search_for(pattern)
        if rects:
            print(f'  Page {page_num}: "{pattern}" found at {rects}')

doc.close()
