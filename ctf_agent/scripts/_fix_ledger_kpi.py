"""2026-08-27 诚实校准：将台账严格 KPI 从虚高的 10 收敛到可复现的 12。

依据：scripts/_verify_presolve_truth.py 权威真值比对（15 题 14 匹配）+ 10733 独立复现。
- 剔除 3 条不可复现（状态改为 ⛔ unreproducible，merge_gate 不再计入）：
  specialcurve2（附件仅模板、实例值丢失）、10732（求解器+附件缺失）、
  10735（pcap 附件缺失）。
- 补入 5 条被误排除的可复现 A/B 类（presolve 真值匹配，零 LLM）：
  exciting_inverse(B)、filterrandom(B)、qiangwang_classic(B)、sheng(A)、upx(A)。
净结果：严格 KPI 10 - 3 + 5 = 12（A 类 5 + B 类 7）。
"""
import hashlib
import re
from pathlib import Path

LEDGER = Path("REAL_SOLVES_LEDGER.md")
text = LEDGER.read_text(encoding="utf-8")

# ── 1) 剔除 3 条不可复现：把其状态行从 ✅ offline_verified 改为 ⛔ unreproducible ──
UNREPRO = {
    "real_crypto_specialcurve2": "附件 SpecialCurve2.py 为恢复的挑战脚本模板，原 n/HINT/C 每次运行随机生成、已永久丢失，无法离线复现",
    "real_crypto_10732": "求解脚本 _solve_10732.py 与 PKCS#1 附件均缺失（data/race_attachments/ 空），无法离线复现",
    "real_crypto_10735": "logbool.pcapng 附件全仓缺失，无法离线复现",
}
for cid, reason in UNREPRO.items():
    pat = re.compile(
        r"(- \*\*状态\*\*：)✅ offline_verified(\n.*?" + re.escape(cid) + r".*?)(\n)",
        re.DOTALL)
    # 直接按区块定位更简单：替换每个无效题块内的状态行
    # 用「题块标题」锚定
    block_pat = re.compile(
        r"(### \d+\. [^\n]*" + re.escape(cid) + r"[^\n]*\n)(.*?)(\n### |\n## )",
        re.DOTALL)
    m = block_pat.search(text)
    if not m:
        print("WARN 未找到题块:", cid)
        continue
    block = m.group(2)
    if "✅ offline_verified" in block:
        block = block.replace(
            "- **状态**：✅ offline_verified",
            "- **状态**：⛔ unreproducible（2026-08-27 诚实校准移出严格 KPI）", 1)
        block += f"\n- **不可复现原因**：{reason}"
        text = text[:m.start()] + m.group(1) + block + m.group(3) + text[m.end():]
        print("demoted:", cid)
    else:
        print("skip (no ✅):", cid)

# ── 2) 补入 5 条可复现 A/B 类 ──
NEW = [
    # 明文 flag 仅存于本地 gitignored data/results/verified_flags.json；
    # 此处只保留题目 id / 类别 / 类型 / 核验方式，避免明文进入仓库（pre-commit 钩子会拦截）。
    ("real_crypto_exciting_inverse", "B", "矩阵求逆",
     "crypto / 矩阵求逆（确定性变换）；presolve 直出，与题面 flag_sha256 逐字匹配"),
    ("real_crypto_filterrandom", "B", "LFSR 噪声恢复",
     "crypto / 双 LFSR 噪声混合恢复（skills/lfsr_filter_recover.py）；重建实例 flag 与题面 flag_sha256 匹配"),
    ("real_crypto_qiangwang_classic", "B", "摩斯+单表替换",
     "crypto / 摩斯解码 + 单表替换（确定性变换）；presolve 直出，与题面 flag_sha256 逐字匹配"),
    ("real_reverse_sheng", "A", "逆向静态分析",
     "reverse / 逆向静态分析（完整攻击链，非源码 grep）；presolve 直出，与题面 flag_sha256 逐字匹配"),
    ("real_reverse_upx", "A", "UPX 脱壳",
     "reverse / UPX 脱壳（完整攻击链，非源码 grep）；presolve 直出，与题面 flag_sha256 逐字匹配"),
]

insert_blocks = []
for cid, cls, typ, method in NEW:
    tag = "A类·完整攻击链" if cls == "A" else "B类·presolve密码学变换"
    blk = (
        f"\n### 11. {cid} 【{tag}】（历年真题 · {typ}）\n\n"
        f"- **来源**：`data/questions_real/` 对应题\n"
        f"- **类型**：{typ}\n"
        f"- **状态**：✅ offline_verified（2026-08-27 诚实校准补入严格 KPI；原被误排除）\n"
        f"- **flag**：`<REDACTED>`（明文见本地 gitignored `data/results/verified_flags.json`，sha256 可核验）\n"
        f"- **核验方式**：{method}\n"
        f"- **可复现命令**：`.venv/Scripts/python.exe scripts/_verify_presolve_truth.py`（15 题真值比对，本题 ✅ 真值匹配）\n"
    )
    insert_blocks.append(blk)

# 在 xuanhun_signin 题块之后、HGAME(外部真题) 之前插入
anchor = "### 11. HGAME2022-Week2 RSA Attack（外部真题"
idx = text.index(anchor)
insert_text = "".join(insert_blocks)
text = text[:idx] + insert_text + "\n" + text[idx:]

# ── 3) 重编号：HGAME 等外部真题 11-15 → 16-20 ──
for old, new in [("### 11. HGAME", "### 16. HGAME"),
                 ("### 12. HGAME", "### 17. HGAME"),
                 ("### 13. HGAME", "### 18. HGAME"),
                 ("### 14. 2022安网杯", "### 19. 2022安网杯"),
                 ("### 15. 西湖论剑2021 FilterRandom", "### 20. 西湖论剑2021 FilterRandom")]:
    text = text.replace(old, new, 1)

LEDGER.write_text(text, encoding="utf-8")
print("ledger rewritten")
