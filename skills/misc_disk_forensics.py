"""misc_disk_forensics skill：磁盘取证（RAID0 恢复 + 镜像分析）。

场景（misc-006『糟糕的磁盘』）：压缩包内 N 个文件名随机的 Linux 磁盘镜像（RAID0），
块大小已知 → 爆破磁盘排列顺序（最多 N! 种）→ 按块交错重组恢复 RAID0 →
搜分区特征（ext4/NTFS 超级块）→ 字符串搜索 key.png/secret/flag。

依赖：纯 Python（struct/re 无外部库）；可选 file 命令识别镜像类型。

用法（skill 调用）：
    params = {'disks': [路径列表], 'block_size': 512*1024, 'search': ['flag', 'key.png', 'secret']}
    result = misc_disk_forensics(params)
"""

import itertools
import os
import re


def raid0_permutations(n: int, max_perms: int = 1000) -> list:
    """生成磁盘排列（n! 种，最多 max_perms 防爆）。"""
    if n > 8:
        return []  # 8! = 40320 太大，提示按提示缩小
    perms = list(itertools.permutations(range(n)))
    return perms[:max_perms]


def raid0_rebuild(disks: list, order: tuple, block_size: int) -> bytes:
    """按排列顺序块交错重组 RAID0。

    RAID0 条带化：数据按 block_size 块轮流写到每个盘（按 order 顺序），
    重组 = 依次从每个盘读一块拼接。
    """
    handles = [open(d, "rb") for d in disks]
    try:
        out = bytearray()
        while True:
            progressed = False
            for i in order:
                chunk = handles[i].read(block_size)
                if chunk:
                    out += chunk
                    progressed = True
            if not progressed:
                break
        return bytes(out)
    finally:
        for h in handles:
            h.close()


def search_partition_features(data: bytes) -> list:
    """搜索分区/文件系统特征。"""
    found = []
    # ext4 超级块: 0x438 处 magic 0xEF53
    for off in range(0, len(data) - 0x440, 0x1000):
        if data[off + 0x438:off + 0x43A] == b"\x53\xef":
            found.append({"type": "ext4", "offset": off, "desc": f"ext4 超级块 @0x{off:x}"})
            break
    # NTFS: 引导扇区 0xEB 0x52 0x90 'NTFS'
    if data[:3] == b"\xeb\x52\x90" and b"NTFS" in data[3:8]:
        found.append({"type": "ntfs", "offset": 0})
    # FAT: 0xEB 0x3C 0x90 'FAT'
    if data[:3] == b"\xeb\x3c\x90" and b"FAT" in data[54:59]:
        found.append({"type": "fat", "offset": 0})
    return found


def search_strings(data: bytes, needles: list, limit: int = 50) -> list:
    """搜索可读字符串中的关键内容（flag/文件名）。"""
    hits = []
    # flag 模式
    for m in re.finditer(rb"(?:flag|ctf|DASCTF)\{[^}\s]{4,}\}", data):
        hits.append({"kind": "flag", "value": m.group(0).decode("utf-8", errors="replace")})
    # 文件名/关键字
    for nd in needles:
        nb = nd.encode() if isinstance(nd, str) else nd
        for m in re.finditer(re.escape(nb), data):
            ctx = data[max(0, m.start() - 10):m.end() + 30]
            hits.append({"kind": "needle", "value": nd,
                         "ctx": ctx.decode("utf-8", errors="replace").strip()})
            if len(hits) >= limit:
                return hits
    return hits


def misc_disk_forensics(params: dict) -> dict:
    """skill 入口：RAID0 恢复 + 磁盘分析。"""
    disks = params.get("disks", [])
    if not disks:
        return {"ok": False, "error": "缺少 disks（镜像文件路径列表）"}
    block_size = int(params.get("block_size", 512 * 1024))
    needles = params.get("search", ["flag", "key.png", "secret"])

    n = len(disks)
    perms = raid0_permutations(n)
    if not perms:
        return {"ok": False, "note": f"{n} 盘排列 {n}! 过大，需按提示缩小候选"}
    print(f"[raid0] {n} 盘，块 {block_size}B，排列数 {len(perms)}")

    best = None
    for order in perms:
        try:
            rebuilt = raid0_rebuild(disks, order, block_size)
        except Exception:
            continue
        feats = search_partition_features(rebuilt)
        # 有文件系统特征 = 排列正确（RAID0 重组后应有合法分区）
        if feats:
            best = {"order": order, "features": feats, "data": rebuilt}
            print(f"[raid0] ✅ 排列 {order} 恢复出分区: {feats[0]['desc']}")
            break
        if best is None:
            best = {"order": order, "features": [], "data": rebuilt}

    if best is None:
        return {"ok": False, "error": "RAID0 重组失败"}

    hits = search_strings(best["data"], needles)
    flags = [h["value"] for h in hits if h["kind"] == "flag"]
    return {
        "ok": True,
        "raid_order": list(best["order"]),
        "partitions": best["features"],
        "findings": hits,
        "flags": flags,
        "note": "若找到分区但挂载需 root/镜像偏移，下一步用 7z/guestfish 挂载提取文件",
    }


def run(params: dict) -> dict:
    """SkillManager 统一入口。"""
    return misc_disk_forensics(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="磁盘取证（RAID0 恢复）")
    parser.add_argument("--disks", required=True, nargs="+", help="磁盘镜像路径（顺序随机）")
    parser.add_argument("--block-size", type=int, default=512 * 1024, help="RAID0 块大小")
    args = parser.parse_args()
    import json

    print(json.dumps(misc_disk_forensics(
        {"disks": args.disks, "block_size": args.block_size}), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
