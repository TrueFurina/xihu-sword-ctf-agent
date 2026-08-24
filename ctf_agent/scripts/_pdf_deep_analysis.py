#!/usr/bin/env python3
"""深度分析 10732 解密 PDF 的 flag 位置"""
import re, zlib, sys, os

pdf_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'tmp_dryrun', '10732', 'decrypted.pdf')
pdf_path = os.path.normpath(pdf_path)

with open(pdf_path, 'rb') as f:
    data = f.read()

print(f'PDF size: {len(data)} bytes')
print(f'Header: {data[:20]}')
print()

# 1. Info dict (obj 1)
obj1_start = data.find(b'1 0 obj')
if obj1_start != -1:
    obj1_end = data.find(b'endobj', obj1_start)
    print('=== Info dict (obj 1) ===')
    print(data[obj1_start:obj1_end+6].decode('latin-1', errors='ignore'))
    print()

# 2. 所有 stream
print('=== All streams ===')
stream_positions = [(m.start(), m.end()) for m in re.finditer(rb'stream\r?\n', data)]
for i, (s_start, s_start_end) in enumerate(stream_positions):
    e = data.find(b'endstream', s_start_end)
    if e == -1:
        continue
    raw_stream = data[s_start_end:e]
    # 尝试解压
    decompressed = None
    try:
        decompressed = zlib.decompress(raw_stream)
    except:
        try:
            decompressed = zlib.decompress(raw_stream, -15)  # raw deflate
        except:
            pass

    if decompressed:
        print(f'Stream {i}: raw={len(raw_stream)}, decompressed={len(decompressed)} bytes')
        text = decompressed.decode('latin-1', errors='ignore')

        # 搜索 Tj/TJ 算子中的文本 (parenthesized strings)
        tj_matches = re.findall(r'\(([^)]*)\)', text)
        meaningful = [t for t in tj_matches if len(t) > 2 and not t.startswith(chr(92)) and not all(c in '()<>{}[]/ ' for c in t)]
        if meaningful:
            print(f'  Text strings ({len(meaningful)}): {meaningful[:30]}')

        # 搜索 hex strings <...> (可能是 UTF-16BE 编码的文本)
        hex_matches = re.findall(r'<([0-9a-fA-F]{4,})>', text)
        for hm in hex_matches[:15]:
            try:
                decoded = bytes.fromhex(hm).decode('utf-16-be', errors='ignore')
                if decoded.strip() and len(decoded.strip()) > 2:
                    print(f'  Hex->UTF16: {decoded[:100]}')
            except:
                pass

        # 搜索 DASCTF/flag/ctf
        for pat in [b'DASCTF', b'flag{', b'ctf{', b'FLAG{', b'DASCTF{']:
            if pat in decompressed:
                idx = decompressed.find(pat)
                print(f'  *** {pat.decode()} FOUND at offset {idx}! ***')
                print(f'  Context: {decompressed[max(0,idx-30):idx+100]}')
    else:
        print(f'Stream {i}: raw={len(raw_stream)} bytes (not zlib)')
        text = raw_stream.decode('latin-1', errors='ignore')
        for pat in ['DASCTF', 'flag{', 'ctf{']:
            if pat in text.lower():
                print(f'  *** {pat} FOUND! ***')

# 3. 检查 XObject/Image
print('\n=== Image objects ===')
img_count = 0
for m in re.finditer(rb'/Subtype\s*/Image', data):
    img_count += 1
    pos = m.start()
    # 找包含这个的 obj
    obj_match = re.search(rb'(\d+)\s+(\d+)\s+obj', data[max(0,pos-500):pos])
    if obj_match:
        obj_num = obj_match.group()
        obj_start = data.rfind(obj_match.group(0), 0, pos)
        obj_end = data.find(b'endobj', pos)
        print(f'Image in obj {obj_num.decode()}:')
        print(data[obj_start:obj_end+6].decode('latin-1', errors='ignore')[:500])
        print()
    else:
        print(f'Image at {pos} (no obj found)')

if img_count == 0:
    print('No image objects found')

# 4. 检查 Catalog 和 Pages 引用
print('\n=== Catalog ===')
for m in re.finditer(rb'/Type\s*/Catalog', data):
    pos = m.start()
    obj_start = data.rfind(b' obj', 0, pos)
    obj_start = data.rfind(b'\n', 0, obj_start) + 1
    obj_end = data.find(b'endobj', pos)
    print(data[obj_start:obj_end+6].decode('latin-1', errors='ignore')[:500])
    print()

# 5. 检查 PDF 的 AcroForm / JS / EmbeddedFile
for keyword in [b'/AcroForm', b'/JavaScript', b'/EmbeddedFile', b'/Annot', b'/URI', b'/OpenAction']:
    if keyword in data:
        pos = data.find(keyword)
        print(f'{keyword.decode()} found at {pos}:')
        print(f'  Context: {data[max(0,pos-50):pos+200].decode("latin-1", errors="ignore")}')
        print()
