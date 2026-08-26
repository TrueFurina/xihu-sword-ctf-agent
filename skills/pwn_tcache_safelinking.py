"""pwn_tcache_safelinking skill：tcache 2.31+ safe-linking 知识卡片（高难题）。

正式赛高难题（决赛堆题必然出现）：glibc 2.31+ 的 tcache safe-linking 异或
保护——旧 2.27 思路（直接改 fd 双链表指针）在 2.31+ 失效，需按 safe-linking
规则构造。本 skill 提供：safe-linking 原理 + 绕过步骤 + 利用链构造流程。

流程（无 gdb 盲打适配）：
1. 识别 libc 版本（pwn_libc_fingerprint——泄露地址/附件 libc.so.6）
2. 2.31+ 判定 safe-linking 生效（tcache_entry next 异或保护）
3. 绕过：fd 泄露/篡改用 PROTECT_PTR(ptr, pos) = ptr ^ pos 逆向
4. 利用链：tcache poisoning / tcache stashing / double free 检测绕过
"""

import re

_SAFE_LINKING_FLOW = """## tcache 2.31+ safe-linking 利用链（知识卡片）

### 1. 判定（libc 版本）
- glibc < 2.31：tcache 无 safe-linking，旧思路（直接改 fd）可用
- glibc >= 2.31：safe-linking 生效——tcache_entry.next 被异或保护
  PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr  （ptr 存储时异或）

### 2. 关键构造（绕过 safe-linking）
- 篡改 tcache_entry.next 时需按异或规则：
  encoded = (chunk_addr >> 12) ^ target_addr
- 常见场景：
  a. UAF 读（泄露真实 fd → 逆向计算 pos >> 12 的 key）
  b. 部分写（覆盖低字节——异或保护只影响高字节，低字节写入仍有效）
  c. tcache poisoning：先泄露 fd 得到 key（key = stored_fd ^ (pos>>12)）

### 3. 利用链（无 gdb 盲打）
- tcache poisoning（改 next → 任意地址分配——需按 safe-linking 编码）
- tcache stashing unlink（large bin 到 tcache——触发 unsorted/large bin 写）
- double free 检测绕过（2.31+ 双链表环检测——需构造合法环）

### 4. 判定式利用（无 gdb 判据）
- 分配后打印泄露：看 fd 是否含 (pos>>12) 高字节（safe-linking 生效证据）
- 篡改 next 后分配：若 crash 在 tcache 取 chunk（异或解码失败）→ 编码错误
- 成功标志：分配返回目标地址（如 __free_hook/system）

### 5. 边界
- 2.31 与 2.32+ 的 safe-linking 相同（2.32 加 tcache key 检测）
- 2.32+ 需同时绕过 tcache key（双链表环检测）——构造合法环或 UAF 泄 key
"""


def pwn_tcache_safelinking(params: dict) -> dict:
    """skill 入口：返回 safe-linking 知识卡片（利用链构造流程）。"""
    libc_version = str(params.get("libc_version", ""))
    scenario = str(params.get("scenario", ""))
    result = {"ok": True, "method": "tcache_safe_linking"}
    result["flow"] = _SAFE_LINKING_FLOW

    # 版本判定提示
    if libc_version:
        try:
            ver_num = float(re.search(r"(\d+\.\d+)", libc_version).group(1))
            result["safe_linking"] = ver_num >= 2.31
            result["note"] = ("safe-linking 生效" if ver_num >= 2.31
                              else "无 safe-linking（旧思路可用）")
        except Exception:  # noqa: BLE001
            result["note"] = "libc 版本解析失败——按 2.31+ 保守处理"
    else:
        result["note"] = "未提供 libc 版本——先 pwn_libc_fingerprint 识别（泄露地址/附件 libc.so.6）"

    # 场景匹配提示
    if "double free" in scenario.lower():
        result["scenario_hint"] = "double free：2.32+ 需绕过 tcache key 检测——构造合法环或 UAF 泄 key"
    elif "poison" in scenario.lower() or "poisoning" in scenario.lower():
        result["scenario_hint"] = "tcache poisoning：next 按 PROTECT_PTR 编码（(pos>>12)^target）"
    elif "stash" in scenario.lower():
        result["scenario_hint"] = "tcache stashing：large bin 到 tcache——unsorted bin 写 /bin/sh 链"
    return result


def run(params: dict) -> dict:
    """SkillManager 统一入口（2026-08-21 补——正式赛 skill 自动加载约定）。"""
    return pwn_tcache_safelinking(params)


def main() -> None:
    import json

    print(json.dumps(pwn_tcache_safelinking(
        {"libc_version": "2.31", "scenario": "tcache poisoning"}), ensure_ascii=False, indent=1)[:500])


if __name__ == "__main__":
    main()
