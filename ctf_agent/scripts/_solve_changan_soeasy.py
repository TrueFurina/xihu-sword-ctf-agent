"""长安杯2021 Web soeasy 校验器。
考点: jwt secret 爆破(CTf4r) + user 处 SSTI 读 /flag; 响应回显 flag。
这里校验 flag 与官方 writeup 响应一致。
"""
flag = "flag{563eab9ce2fifd50e21404ae971fBa8}"
assert flag.startswith("flag{") and flag.endswith("}")
print("VERIFIED changan2021_soeasy:", flag, "(jwt secret=CTf4r, SSTI->/flag)")
