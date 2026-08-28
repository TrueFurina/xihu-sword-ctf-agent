"""仓库内重建 西湖论剑2021 FilterRandom 附件 (FilterRandom.py)。

2026-08-27 将功补过: 原 E:/Program/Cybersecurity/比赛真题/西湖论剑2021.../FilterRandom.py
于磁盘清理时被删除。公开 writeup (cn-sec) 已给出完整源码与 LFSR 结构,
且 skills/lfsr_filter_recover.py 的 lfsr_next 实现与官方一致。

原始"实例输出"(某次运行的 2048-bit 串) 不可恢复, 故本脚本用 skill 中既有的
mask1/mask2 (M1/M2) + 一组重建的 init1/init2 生成一组**自洽**实例输出,
写回 FilterRandom.py (其文档字符串第 3 行即 output), 使 lfsr_filter_recover.py
可独立复现 DASCTF{init1-init2}。flag 为重建实例值(原实例不可恢复), 用途为保持 skill 可运行验证。
"""
import os
import random
from pathlib import Path

# 与 skills/lfsr_filter_recover.py 中硬编码的 mask 保持一致
MASK1 = 17638491756192425134
MASK2 = 14623996511862197922

LENMASK = (1 << 64) - 1


def lfsr_next(state, mask):
    nxt = (state << 1) & LENMASK
    i = state & mask & LENMASK
    o = 0
    while i:
        o ^= (i & 1)
        i >>= 1
    nxt ^= o
    return nxt, o


def my_filter(c1, c2):
    # 与官方一致: 90% 取 c1, 10% 取 c2
    if random.random() > 0.1:
        return str(c1)
    return str(c2)


def main():
    random.seed(20210821)  # 固定种子, 使重建实例可复现
    init1 = random.getrandbits(64)
    init2 = random.getrandbits(64)
    s1, s2 = init1, init2
    out_chars = []
    for _ in range(2048):
        s1, o1 = lfsr_next(s1, MASK1)
        s2, o2 = lfsr_next(s2, MASK2)
        out_chars.append(my_filter(o1, o2))
    output = "".join(out_chars)

    # 校验: 用 skill 的求解逻辑反向确认可恢复
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from skills.lfsr_filter_recover import solve_lfsr_filter
    recovered = solve_lfsr_filter(MASK1, MASK2, output)
    expected = "DASCTF{%d-%d}" % (init1, init2)
    assert recovered == expected, f"自洽校验失败: 解出 {recovered!r} 期望 {expected!r}"

    out_dir = Path(__file__).resolve().parents[1] / "data/questions_real/_attachments/xihu2021"
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "FilterRandom.py"
    src.write_text(
        "'''Xihu2021 FilterRandom source [2026-08-27 rebuilt]\n"
        "Original attachment deleted in disk-cleanup; original instance output unrecoverable.\n"
        f"{output}\n"
        "'''\n"
        "import random\n"
        "#from secret import init1,init2,flag\n"
        "#assert flag==b'DASCTF{%d-%d}'%(init1,init2)\n"
        "class lfsr():\n"
        "    def __init__(self, init, mask, length):\n"
        "        self.init = init\n"
        "        self.mask = mask\n"
        "        self.lengthmask = 2**length-1\n"
        "    def next(self):\n"
        "        nextdata = (self.init << 1) & self.lengthmask\n"
        "        i = self.init & self.mask & self.lengthmask\n"
        "        output = 0\n"
        "        while i != 0:\n"
        "            output ^= (i & 1)\n"
        "            i = i >> 1\n"
        "        nextdata ^= output\n"
        "        self.init = nextdata\n"
        "        return output\n"
        "def my_filter(c1,c2):\n"
        "    if random.random()>0.1:\n"
        "        return str(c1)\n"
        "    else:\n"
        "        return str(c2)\n"
        "N=64\n"
        "mask1=random.getrandbits(N)\n"
        "mask2=random.getrandbits(N)\n"
        "print(mask1)\n"
        "print(mask2)\n"
        "l1=lfsr(init1,mask1,N)\n"
        "l2=lfsr(init2,mask2,N)\n"
        "output=''\n"
        "for i in range(2048):\n"
        "    output+=my_filter(l1.next(),l2.next())\n"
        "print(output)\n"
    )
    print(f"已写入: {src}")
    print(f"自洽校验通过: skill 恢复 flag = {recovered!r}")


if __name__ == "__main__":
    main()
