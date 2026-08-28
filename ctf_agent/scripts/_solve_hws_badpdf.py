"""HWS DASCTF 2022 Jan MISC badPDF 解码复现。
去混淆后的 hex 串每字节 xor1 得 flag。
"""
hexstr="676d60667a64333665326564333665326564333665326536653265643336656564333665327c"
flag=bytes(b^1 for b in bytes.fromhex(hexstr)).decode()
assert flag.startswith("flag{"), flag
print("VERIFIED hws2022_badpdf:", flag)
