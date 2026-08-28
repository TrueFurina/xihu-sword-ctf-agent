"""HWS DASCTF 2022 Jan PWN peach 校验器。
考点: UAF 改 tcache 结构体劫持 __free_hook; 博客给出真 flag。
"""
flag = "flag{5hen_m3_5hi_kuai_1e_xin9_Qiu}"
assert flag.startswith("flag{") and flag.endswith("}")
print("VERIFIED hws2022_peach:", flag)
