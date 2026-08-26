# -*- coding: utf-8 -*-
"""10733 CRYPTO-02 "How many rot are there" — 可复现离线核验脚本。

真题来源：data/race_details/10733.json + 附件 data/race_attachments/10733_How_many_rot_are_there的附件
攻击链（已在本机跑通）：
  1) hint ≡ e^q·p + e^{2q} (mod n)  ->  W = e^n mod n  ->  p = gcd(W²-hint, n)
  2) e=65536=2^16，p,q 均 3 mod 4：在奇数阶子群 s=(p-1)/2 求逆使 2^15·inv≡1 (mod s)
     -> c^inv ≡ m² (mod p)，CRT 得 m² mod n，一轮 Rabin 得 m
  3) 明文 m 是 ROT13 编码：QNFPGS{...} = rot13(DASCTF{...})，题名 "How many rot" 即提示。
     ROT13 只转字母、不动数字 -> 规范 flag = DASCTF{<redacted>}（明文见本地 gitignored verified_flags.json）

运行：.venv/Scripts/python.exe scripts/verify_10733.py
"""
import sys, json
sys.path.insert(0, ".")
import skills.crypto_high_exponent as sk

hint = 101048855492044571417475830924088947184757234444475406804947498377420789778570832667138477666669908690663759417316798982038542431531087217671616502327573935462498550576600180793553880691247281813287212166428236802504214599757066100450668324529765827891463527861160593648623157792143035729770978865516948880313
c = 62214676810380175097525195047581624344610596576389901532958749194333175927146005969879818861882074690471600028484419966943711467342568120045965690332607166015419112255944582319675084071747302548088333383655637474764450810187215177625206094644430662667402073753343732910706186228919546522301643978766618493433
n = 131232786046474875167899992758388342524496883222860498694293714537118780151392850883679257361099172761516964104115167485944225089583991161038144993589322315250529302275646269196618503385962458635181473103926087951239559460161218447795578503981054097990206859884036249764383918404640987230150854235563692800669
e = 65536

def codecs_rot(s, k, digits=False):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        elif digits and ch.isdigit():
            out.append(chr((ord(ch) - 48 + 5) % 10 + 48))
        else:
            out.append(ch)
    return "".join(out)

fr = sk.factor_from_hint(hint, e, n)
assert fr.get("ok"), f"分解失败: {fr}"
p, q = fr["p"], fr["q"]
res = sk.recover_via_odd_subgroup(c, e, p, q, ["DASCTF{", "flag{", "ctf{", "QNFPGS{", "SYNT{"])
assert res.get("ok"), f"解密失败: {res}"
plain = res["flag"]
rot13 = codecs_rot(plain, 13)          # 字母转，数字不动 -> 规范 flag
rot18 = codecs_rot(plain, 13, True)    # 字母+数字都转（非标准，备查）
canonical = rot13 if rot13.startswith("DASCTF{") else rot18
print(json.dumps({
    "ok": True,
    "plaintext_rot13_encoded": plain,
    "flag_canonical": canonical,
    "flag_rot18_variant": rot18,
    "via": res["via"],
}, ensure_ascii=False, indent=2))
# 断言：规范 flag 必须带 DASCTF{ 前缀
assert canonical.startswith("DASCTF{"), "规范 flag 前缀异常"
print("VERIFIED:", canonical)
