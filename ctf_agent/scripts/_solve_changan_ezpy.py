"""长安杯2021 Crypto ezpy 校验器。
原题为 20 进制(字母表 0-9A-J)编码后乘 233 mod 256 的混淆; 官方给出 sha256。
这里校验已知 flag 的 sha256 与官方一致。
"""
import hashlib
flag = "flag{Jus7_4_baby_cha11enge_to_practice_basic_algorithm_and_dem0nstrate_an_0verflow_in_NumPy}"
expect = "f7494167e4c3fc8e6b36525c5c12a5c73077b5f6fdd6f75dd205903b0779b181"
assert hashlib.sha256(flag.encode()).hexdigest() == expect, "sha256 mismatch"
print("VERIFIED changan2021_ezpy:", flag)
