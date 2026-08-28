#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成从本机已抽取 writeup 文本中确认的 5 道真题 (续十)。
约定: JSON 的 flag 字段存明文 flag 的 sha256; 明文落 gitignored 的 _attachments。
所有 flag 均来自官方/semi-official writeup 明文, 属真实历史赛题还原。
"""
import hashlib, json, os

BASE = os.path.abspath("ctf_agent/data/questions_real")

# (pid, cat, title, category_label, plaintext_flag, flag_pattern, difficulty, source, desc)
ITEMS = [
    ("real_reverse_vnctf_timeflies", "reverse",
     "VNCTF2022 TimeFlies (pyc 反编译 reverse)",
     "reverse",
     "VNCTF{TimeFl20211205ightMachine}",
     r"VNCTF\{[^}]+\}",
     "MEDIUM",
     "VNCTF2022 官方 writeup (pyc 反编译, python3.8)",
     "附件为 python3.8 编译的 pyc, 用 uncompyle6 反编译后得到逻辑, 还原 TimeFlies 题意即得 flag。writeup 明文给出真 flag。"),

    ("real_misc_vnctf_vnloan", "misc",
     "VNCTF2022 VNloan (区块链/目录重建 misc)",
     "misc",
     "vnctf{d23903879df57503879bcdf1efc141fe}",
     r"vnctf\{[0-9a-f]+\}",
     "MEDIUM",
     "VNCTF2022 writeup (BlockChain/VNloan, 依 res 序列重建目录树)",
     "VNCTF2022 区块链类题 VNloan: 依链上路径序列 res 重建文件夹结构, 末节点文件名即 flag 片段。writeup 明文给出真 flag。"),

    ("real_pwn_changan2021_pwn3", "pwn",
     "长安杯2021 pwn3 (游戏类 PWN)",
     "pwn",
     "flag{3901afdc7f79dedfdb062a241eb3a575}",
     r"flag\{[0-9a-f]{32}\}",
     "MEDIUM",
     "长安杯2021 writeup (pwn3 游戏型 PWN, oPwn Platform 打 exp)",
     "长安杯2021 pwn3 为游戏类 PWN, 编写 exp 经 oPwn Platform 工具执行后拿到 flag。writeup 明文给出真 flag。"),

    # 注: 安洵杯2020 easyzip 已存在于此前会话提交的 real_anxun2020_easyzip.json (旧 schema), 此处不再重复生成。
    ("real_crypto_anxun2020_aes", "crypto",
     "安洵杯2020 crypto (AES-CBC 已知明密文恢复位移)",
     "crypto",
     "d0g3{71b2b56162a46397d979de964c}",
     r"d0g3\{[0-9a-f]+\}",
     "MEDIUM",
     "安洵杯2020 官方 writeup (AES-CBC, 已知密文/明文/私钥求位移, mbruteforce 恢复破损 hex)",
     "安洵杯2020 crypto 题: 已知密文/明文/私钥, 依 AES-CBC 原理求位移, 用 mbruteforce 在 table='0123456789abcdef' 上恢复破损 hex flag (原 flag 中 ** 段为缺失位)。writeup 明文给出真 flag d0g3{71b2b56162a46397d979de964c}。"),
]

def main():
    for pid, cat, title, catlabel, plain, pat, diff, src, desc in ITEMS:
        h = hashlib.sha256(plain.encode()).hexdigest()
        adir = os.path.join(BASE, "_attachments", cat, pid)
        os.makedirs(adir, exist_ok=True)
        with open(os.path.join(adir, "flag.txt"), "w", encoding="utf-8") as f:
            f.write(plain + "\n")
        obj = {
            "id": pid,
            "provenance": "real_past_ctf",
            "category": catlabel,
            "title": title,
            "description": desc,
            "flag": h,
            "flag_pattern": pat,
            "attachments": [f"data/questions_real/_attachments/{cat}/{pid}/flag.txt"],
            "difficulty": diff,
            "flag_sha256": h,
            "verified_solver": False,
            "source": src,
        }
        out = os.path.join(BASE, cat, pid + ".json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("WROTE", out, "sha256", h[:12], "plain", plain)

if __name__ == "__main__":
    main()
