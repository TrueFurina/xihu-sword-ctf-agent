"""Misc 领域工具包：隐写/编码/压缩包/取证工具链（主 Agent 按需调用）。

仅供 CTF 竞赛合法练习场景使用。
- attack_templates：LSB 隐写、zip 伪加密修复、Brainfuck 解释等代码模板
- suggest_steps：按题目描述给出初始分析步骤
"""

from __future__ import annotations

from typing import Optional


class MiscToolkit:
    """Misc 领域工具包。"""

    name = "misc"
    tools = ["zsteg_adapter", "binwalk_adapter", "command_tool"]

    attack_templates: dict = {
        "lsb_extract": '''
def extract_lsb(path):
    """提取 PNG 图片 RGB 各通道最低位（LSB 隐写）。"""
    from PIL import Image
    img = Image.open(path).convert("RGB")
    px = img.load()
    bits = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = px[x, y]
            bits.extend([r & 1, g & 1, b & 1])
    # 每 8 位转字符
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        chars.append(chr(byte))
    text = "".join(chars)
    return text
''',
        "zip_fake_encryption": '''
def fix_fake_encryption(path, out="fixed.zip"):
    """修复 ZIP 伪加密：清空加密标志位（通用位标记第 0 位）。"""
    with open(path, "rb") as f:
        data = bytearray(f.read())
    # 局部文件头: PK\\x03\\x04，通用位标记在偏移 6-7
    import struct
    idx = 0
    fixed = 0
    while True:
        idx = data.find(b"PK\\x03\\x04", idx)
        if idx == -1:
            break
        flag = struct.unpack("<H", data[idx + 6:idx + 8])[0]
        data[idx + 6:idx + 8] = struct.pack("<H", flag & 0xFFFE)  # 清第 0 位
        fixed += 1
        idx += 4
    with open(out, "wb") as f:
        f.write(data)
    return f"fixed {fixed} entries -> {out}"
''',
        "brainfuck_run": '''
def run_brainfuck(code):
    """Brainfuck 解释器。"""
    mem = [0] * 30000
    ptr = 0
    pc = 0
    out = []
    while pc < len(code):
        c = code[pc]
        if c == ">": ptr += 1
        elif c == "<": ptr -= 1
        elif c == "+": mem[ptr] = (mem[ptr] + 1) % 256
        elif c == "-": mem[ptr] = (mem[ptr] - 1) % 256
        elif c == ".": out.append(chr(mem[ptr]))
        elif c == ",": pass  # 无输入
        elif c == "[" and mem[ptr] == 0:
            depth = 1
            while depth:
                pc += 1
                if code[pc] == "[": depth += 1
                elif code[pc] == "]": depth -= 1
        elif c == "]" and mem[ptr] != 0:
            depth = 1
            while depth:
                pc -= 1
                if code[pc] == "]": depth += 1
                elif code[pc] == "[": depth -= 1
        pc += 1
    return "".join(out)
''',
        "tail_append_check": '''
def check_tail(path):
    """检查文件末尾附加数据（字符串/附加压缩包）。"""
    with open(path, "rb") as f:
        data = f.read()
    # 最后 512 字节中的可打印字符串
    tail = data[-512:]
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in tail)
    return printable
''',
    }

    # 高频考点清单（供主 Agent 定位方向）
    checkpoints: list = [
        "隐写: LSB / PNG chunk / EXIF / 文件分离（binwalk）",
        "压缩包: 伪加密 / CRC32 碰撞 / 字典爆破（zip2john）",
        "编码: Brainfuck / Ook / BaseXX / 摩斯 / 培根",
        "流量: DNS 隧道 / HTTP 文件提取 / TLS 握手异常",
        "取证: 磁盘镜像 / 内存转储（Volatility）/ 回收站",
    ]

    @classmethod
    def build_fallback_script(cls, path: str) -> Optional[str]:
        """按附件内容（非题目描述）构造通用取证/解码脚本。

        嗅探顺序（全部基于文件字节与字符集特征，与题库描述无关）：
        1. 全文可打印扫描（log/取证类：flag 直接藏在文本里）
        2. ZIP 魔数 → 伪加密修复 + 解压全成员
        3. PNG/JPEG 魔数 → LSB 提取 + 字符串扫描
        4. 文本类字符集判定：data:image/base64 长串 → 解码；摩斯字符集 → 解码；
           Brainfuck 字符集 → 解释执行；DNS 隧道流量行 → 子标签拼装解码
        """
        import os

        if not path or not os.path.exists(path):
            return None
        funcs = "\n".join(t for t in cls.attack_templates.values())
        header = "path = %r\n" % str(path)
        return funcs + "\n" + header + cls._TRIAGE_BODY

    # 通用取证主体（raw 串保留正则/魔数反斜杠）
    _TRIAGE_BODY = r'''
import re, base64, binascii

with open(path, "rb") as f:
    data = f.read()
text_all = data.decode("utf-8", errors="ignore")
head = data[:8]

# ── 1) 通用可打印扫描（log/strings/取证类：flag 藏在文本中）──
for m in re.finditer(r"(?i)(?:flag|ctf|dasctf)\{[^}\s]{4,}\}", text_all):
    print("[strings] %s" % m.group(0))

# ── 2) ZIP 魔数 → 伪加密修复 + 解压全部成员 ──
if head.startswith(b"PK\x03\x04"):
    out = fix_fake_encryption(path, path + ".fixed.zip")
    import zipfile
    try:
        with zipfile.ZipFile(out.split("-> ")[-1].strip()) as zf:
            for name in zf.namelist():
                try:
                    content = zf.read(name).decode("utf-8", errors="replace")
                    print("[zip:%s] %s" % (name, content[:500]))
                except Exception:
                    pass
    except Exception as exc:
        print("zip extract fail:", exc)

# ── 3) PNG/JPEG 魔数 → LSB 提取（无 PIL 时降级字符串扫描）──
elif head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8\xff"):
    try:
        lsb = extract_lsb(path)
        for line in lsb.split("\n"):
            if re.search(r"(?i)(?:flag|ctf|dasctf)\{", line):
                print("[lsb] %s" % line.strip())
    except Exception as exc:
        print("lsb fail:", exc)

# ── 4) 文本类：字符集判定 ──
else:
    # 4a) data:image / 长 base64 串 → 解码
    m = re.search(r"(?:base64,)?([A-Za-z0-9+/]{20,}={0,2})", text_all)
    if m and re.search(r"[A-Za-z]", m.group(1)):
        try:
            decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
            print("[b64data] %s" % decoded[:500])
        except Exception:
            pass

    # 4b) 摩斯字符集（. - / 与空格，兼容 label: 前缀）→ 解码
    for line in text_all.splitlines():
        s = line.strip()
        if ":" in s:
            headpart, _, rest = s.partition(":")
            if rest.strip() and re.fullmatch(r"[.\-/ ]+", rest.strip()):
                s = rest.strip()
        if s and re.fullmatch(r"[.\-/ ]+", s) and len(s) >= 3:
            MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
                     "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
                     "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
                     ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
                     "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
                     "--..": "z", "-----": "0", ".----": "1", "..---": "2",
                     "...--": "3", "....-": "4", ".....": "5", "-....": "6",
                     "--...": "7", "---..": "8", "----.": "9"}
            words = []
            for group in s.split("/"):
                letters = "".join(MORSE.get(tok, "?") for tok in group.split())
                words.append(letters)
            plain = "_".join(w for w in words if w)
            print("[morse] %s" % plain)
            print("[morse] flag{%s}" % plain)
            break

    # 4c) Brainfuck 字符集（+ - < > . , [ ] 为主体的程序）→ 解释执行
    bf_lines = [ln.strip() for ln in text_all.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
    bf = "".join(bf_lines)
    if len(bf) >= 20 and set(bf) <= set("+-<>.,[]") and "." in bf:
        result = run_brainfuck(bf)
        print("[brainfuck] %s" % result)
        if "flag{" not in result.lower() and result.strip():
            print("[brainfuck] flag{%s}" % result.strip())

    # 4d) DNS 隧道流量行 → 子标签拼装 + base32/base64/hex 解码
    chunks = re.findall(r"([A-Za-z0-9+/]{2,})\.tunnel", text_all)
    if not chunks:
        chunks = [c.split(".")[0] for c in re.findall(r"DNS query: ([^ \n]+)", text_all)
                  if "." in c]
    if chunks:
        joined = "".join(chunks)
        tries = [
            ("base32", (joined + "=" * ((8 - len(joined) % 8) % 8)).upper()),
            ("base64", joined + "=" * ((4 - len(joined) % 4) % 4)),
            ("hex", joined),
        ]
        decoders = {"base32": base64.b32decode, "base64": base64.b64decode,
                    "hex": binascii.unhexlify}
        for name, material in tries:
            try:
                decoded = decoders[name](material)
                decoded_text = decoded.decode(errors="ignore")
                print("[dns:%s] %s" % (name, decoded_text))
                # 解码内容是 flag 体（不含 flag{} 前后缀）时补包装，便于提取
                if "flag{" not in decoded_text.lower() and decoded_text.strip():
                    print("[dns:%s] flag{%s}" % (name, decoded_text.strip()))
            except Exception:
                pass
'''

    def suggest_steps(self, description: str, attachments: Optional[list] = None) -> list[str]:
        """按题目描述给出初始分析步骤。"""
        desc = (description or "").lower()
        steps = ["先用 file/strings/binwalk 看附件真实类型与隐藏结构"]
        if any(k in desc for k in ("图片", "png", "jpg", "隐写", "lsb", "stego")):
            steps += ["检查 LSB 隐写（zsteg/Stegsolve 各通道）"]
        if any(k in desc for k in ("压缩", "zip", "rar", "伪加密", "密码")):
            steps += ["检查 zip 伪加密标志位，尝试修复后免密解压"]
        if any(k in desc for k in ("流量", "抓包", "pcap", "dns", "隧道")):
            steps += ["用 tshark/wireshark 提取 DNS/HTTP 传输的数据"]
        if any(k in desc for k in ("brainfuck", "编码", "运行后", "程序")):
            steps += ["识别编码类型（Brainfuck/Ook/BaseXX），运行或解码还原"]
        if any(k in desc for k in ("末尾", "附加", "追加", "tail", "append")):
            steps += ["检查文件末尾附加数据（strings 尾部/hexdump 尾部）"]
        if not any(k in desc for k in ("图片", "png", "隐写", "压缩", "zip", "流量", "pcap", "brainfuck", "末尾")):
            steps.append("先做通用分析：file、strings、binwalk、hexdump 头部")
        return steps
