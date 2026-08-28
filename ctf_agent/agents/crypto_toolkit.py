"""Crypto 领域工具包：加密算法模板 + 攻击方法（主 Agent 按需调用）。

仅供 CTF 竞赛合法练习场景使用。
- attack_templates：RSA/AES/移位/哈希/编码等攻击方法与代码模板
- suggest_steps：按题目描述给出初始攻击步骤建议
"""

from __future__ import annotations

from typing import Optional


class CryptoToolkit:
    """Crypto 领域工具包。"""

    name = "crypto"
    tools = ["openssl_adapter", "python_crypto"]

    # 攻击方法模板（代码片段，供沙盒执行）
    attack_templates: dict = {
        "caesar": '''
def caesar_bruteforce(ct):
    """凯撒暴力破解：尝试全部 26 种位移。"""
    import string
    for shift in range(26):
        pt = "".join(
            chr((ord(c) - 97 + shift) % 26 + 97) if c in string.ascii_lowercase
            else chr((ord(c) - 65 + shift) % 26 + 65) if c in string.ascii_uppercase
            else c
            for c in ct
        )
        if "flag" in pt.lower():
            return pt, shift
    return None, None
''',
        "phi_known_inv": '''
def _solve_phi_inv(e, phi, c, pinv, qinv):
    """ExcitingInverse 内联解：已知 phi + pinv/qinv 恢复 n 后解密。
    推导：k=p-qinv → p*pinv-1=(p-qinv)*q → pq=p*pinv+qinv*q-1；
    phi=pq-p-q+1 联立 → B*q^2-(phi+B-A)*q+(phi*(1+A)-A)=0（A=pinv-1,B=qinv-1）。"""
    import gmpy2
    A = pinv - 1
    B = qinv - 1
    Cq = B
    Cb = -(phi + B - A)
    Cc = phi * (1 + A) - A
    D = Cb * Cb - 4 * Cq * Cc
    if D < 0:
        return None
    d = int(gmpy2.isqrt(D))
    if d * d != D:
        return None
    for q in (( -Cb + d) // (2 * Cq), (-Cb - d) // (2 * Cq)):
        if q <= 1:
            continue
        num = phi - q * B
        if num % A != 0:
            continue
        p = num // A
        if p <= 1 or (p - 1) * (q - 1) != phi:
            continue
        n = p * q
        if n != p * pinv + qinv * q - 1:
            continue
        dd = int(gmpy2.invert(e, phi))
        m = int(gmpy2.powmod(c, dd, n))
        try:
            return bytes.fromhex(hex(m)[2:]).decode("utf-8", errors="ignore")
        except Exception:
            return str(m)
    return None
''',
        "lfsr_filter": '''
def solve_lfsr_filter(mask1, mask2, out):
    """西湖论剑2021 FilterRandom：90/10 噪声混合双 64-bit LFSR 恢复 init1/init2。
    思路：l1 占 90% 位——随机抽 64 个位置构造 F2 线性方程（单位向量法系数矩阵），
    全局验证匹配率>88% 即认定 init1；l1 预测与观测不同的位置 = l2 真实输出位（100% 正确），
    直接解 l2。返回 'DASCTF{init1-init2}'。"""
    import random
    LENMASK = (1 << 64) - 1
    def lfsr_next(state, mask):
        nxt = (state << 1) & LENMASK
        i = state & mask & LENMASK
        o = 0
        while i:
            o ^= (i & 1); i >>= 1
        nxt ^= o
        return nxt, o
    def simulate(init, mask, n):
        state = init; bits = []
        for _ in range(n):
            state, o = lfsr_next(state, mask); bits.append(o)
        return bits
    def build_coeff(mask, T):
        c = [[0]*64 for _ in range(T)]
        for j in range(64):
            b = simulate(1 << j, mask, T)
            for t in range(T): c[t][j] = b[t]
        return c
    def solve_from(coeff, positions):
        rows = [(list(coeff[t]), b & 1) for t, b in positions]
        pivots = {}
        for x, bb in rows:
            for p in sorted(pivots):
                if x[p]:
                    x2, b2 = pivots[p]
                    for q in range(64): x[q] ^= x2[q]
                    bb ^= b2
            try: p = next(q for q in range(64) if x[q])
            except StopIteration: continue
            pivots[p] = (x, bb)
        init = [0]*64
        for p in sorted(pivots, reverse=True):
            x, b = pivots[p]; val = b
            for q in range(p+1, 64):
                if x[q]: val ^= init[q]
            init[p] = val
        return sum(init[j] << j for j in range(64))
    obs = [int(c) for c in out.strip()]
    C1 = build_coeff(mask1, 2048)
    random.seed(2026)
    best = None
    for trial in range(5000):
        pos = random.sample(range(2048), 64)
        cand = solve_from(C1, [(t, obs[t]) for t in pos])
        sim = simulate(cand, mask1, 2048)
        if sum(1 for a, b in zip(sim, obs) if a == b) > 1800:
            best = cand; break
    if best is None: return None
    sim1 = simulate(best, mask1, 2048)
    diff = [t for t in range(2048) if sim1[t] != obs[t]]
    if len(diff) < 64: return None
    C2 = build_coeff(mask2, 2048)
    for trial in range(2000):
        pos = random.sample(diff, 64)
        c2 = solve_from(C2, [(t, obs[t]) for t in pos])
        s2 = simulate(c2, mask2, 2048)
        if sum(1 for t in diff if s2[t] == obs[t]) == len(diff):
            return 'DASCTF{%d-%d}' % (best, c2)
    return None
''',
        "legendre_quadratic_residue": '''
def legendre_quadratic_residue(phi, N, enc):
    """二次剩余逐位加密（玄盾杯 SimpleLegendre 类）：已知 phi、N、密文列表。
    make_key 保证 x 对 p、q 均为非二次剩余（Legendre(x|p)=Legendre(x|q)=-1），
    且 x^(br+bi) 的 Legendre 符号 = (-1)^bi，故 Legendre(c|p)=+1 → bit 0，-1 → bit 1。
    由 phi 与 N 恢复 p、q（p+q=N-phi+1，判别式=(p+q)^2-4N 完全平方），
    对每个 c 计算 Legendre(c|p)=pow(c,(p-1)//2,p)，恢复二进制明文。"""
    import gmpy2
    s = N - phi + 1  # p + q
    d = gmpy2.isqrt(s * s - 4 * N)
    if d * d != s * s - 4 * N:
        return None
    p = (s + d) // 2
    if p <= 1 or p * (s - p) != N:
        return None
    bits = []
    for c in enc:
        bits.append('0' if pow(int(c), (p - 1) // 2, p) == 1 else '1')
    m = int(''.join(bits), 2)
    try:
        return bytes.fromhex(hex(m)[2:]).decode('utf-8', errors='ignore')
    except Exception:
        return None
''',
        "vigenere": '''
def vigenere_crack(cipher, key_len=None, max_key_len=12):
    """维吉尼亚密码频率分析破解：恢复密钥后解密，返回含 flag 的明文。"""
    import re
    letters = [c for c in cipher if c.isalpha()]
    if not letters:
        return ""
    EN = {'e':12.7,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,'s':6.3,'h':6.1,'r':6.0,'d':4.3,'l':4.0,'c':2.8,'u':2.8,'m':2.4,'w':2.4,'f':2.2,'g':2.0,'y':2.0,'p':1.9,'b':1.5,'v':1.0,'k':0.8,'j':0.15,'x':0.15,'q':0.1,'z':0.07}
    def chi2(text):
        n = len(text)
        if n == 0:
            return 1e9
        total = 0
        for l, p in EN.items():
            exp = n * p / 100
            obs = text.count(l)
            if exp > 0:
                total += (obs - exp) ** 2 / exp
        return total
    def decrypt(cipher, key):
        out, ki = [], 0
        for ch in cipher:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                shift = ord(key[ki % len(key)].upper()) - ord('A')
                ki += 1
                out.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                out.append(ch)
        return ''.join(out)
    best_result = ""
    lengths = [key_len] if key_len else range(1, max_key_len + 1)
    for klen in lengths:
        key = ""
        for pos in range(klen):
            group = [c.lower() for c in letters[pos::klen]]
            best = (1e18, 'A')
            for shift in range(26):
                dec = ''.join(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')) for ch in group)
                s = chi2(dec)
                if s < best[0]:
                    best = (s, chr(ord('A') + shift))
            key += best[1]
        plain = decrypt(cipher, key)
        if "flag" in plain.lower():
            return plain
        if not best_result or len([c for c in plain if c.isalpha()]) > len([c for c in best_result if c.isalpha()]):
            best_result = plain
    return best_result
''',
        "rsa_common_modulus": '''
def common_modulus(c1, c2, e1, e2, n):
    """RSA 共模攻击：扩展欧几里得求 s1*e1 + s2*e2 = 1，恢复明文。"""
    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x1, y1 = egcd(b, a % b)
        return g, y1, x1 - (a // b) * y1
    g, s1, s2 = egcd(e1, e2)
    if s1 < 0:
        c1 = pow(c1, -1, n); s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n); s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m
''',
        "rsa_small_e": '''
def small_e(c, e, m_bits_hint=None):
    """RSA 小指数攻击：m^e < n 时直接开 e 次方。"""
    # 整数二分开方（避免大整数 float 溢出：round(n**(1.0/k)) 对 1024 位会 OverflowError）
    def iroot(k, x):
        hi = 1 << ((x.bit_length() + k - 1) // k)
        lo = 0
        while hi - lo > 1:
            mid = (hi + lo) // 2
            if mid ** k <= x:
                lo = mid
            else:
                hi = mid
        return lo
    m = iroot(e, c)
    if pow(m, e) == c:
        return m
    return None
''',
        "rsa_wiener": '''
def wiener_attack(n, e, c):
    """RSA Wiener 攻击：d < n^0.25 时用连分数展开 e/n 恢复 d。"""
    def cf(n, d):
        while d:
            q, r = divmod(n, d)
            yield q
            n, d = d, r
    def convs(cf):
        n0, d0, n1, d1 = 0, 1, 1, 0
        for q in cf:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield n1, d1
    import math
    for k, d in convs(cf(e, n)):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root = math.isqrt(disc)  # 整数平方根（避免大整数 float 溢出）
        if root * root != disc:
            continue
        p = (s + root) // 2
        if p * ((s - root) // 2) == n:
            m = pow(c, d, n)
            return m
    return None
''',
        "hash_crack": '''
def crack_hash(target, words):
    """哈希爆破：常见弱密码字典。"""
    import hashlib
    for w in words:
        if hashlib.md5(w.encode()).hexdigest() == target:
            return w
        if hashlib.sha1(w.encode()).hexdigest() == target:
            return w
    return None
''',
        "base64_multi": '''
def decode_multi_layer(s, max_layers=20):
    """多层编码解码：url/hex/base64 循环，只接受更可读的结果（防 base64 假解码）。"""
    import base64, binascii, urllib.parse, re
    text = s
    def printable_ratio(t):
        if not t:
            return 0.0
        ascii_cnt = sum(1 for c in t if 32 <= ord(c) < 127)
        return ascii_cnt / len(t)
    for _ in range(max_layers):
        if re.search(r"(?i)(?:flag|ctf|dasctf){", text):
            return text
        best = None
        best_ratio = printable_ratio(text)
        # 按特征优先：hex / url / base64（base64 会假解码，需校验可读性提升）
        candidates = []
        try:
            candidates.append(("hex", binascii.unhexlify(text).decode("utf-8", errors="ignore")))
        except Exception:
            pass
        try:
            candidates.append(("url", urllib.parse.unquote(text)))
        except Exception:
            pass
        try:
            if len(text) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
                candidates.append(("base64", base64.b64decode(text).decode("utf-8", errors="ignore")))
        except Exception:
            pass
        for name, new in candidates:
            if new == text:
                continue
            ratio = printable_ratio(new)
            if ratio >= best_ratio and ratio > 0.5:
                best = new
                best_ratio = ratio
        if best is None:
            break
        text = best
    # ROT13 收尾：base64 解码出 synt{...}（ROT13 的 flag{）时自动还原
    if text.startswith("synt{") or text.startswith("SYNT{"):
        out = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                out.append(chr((ord(ch) - base + 13) % 26 + base))
            else:
                out.append(ch)
        text = "".join(out)
    return text
''',
    }

    # 通用弱口令字典（hash 爆破用——仅收录公开常见弱口令，禁止塞题库答案）
    COMMON_WORDS: list = [
        "123456", "12345678", "123456789", "password", "qwerty", "admin",
        "admin123", "root", "toor", "letmein", "welcome", "monkey",
        "abc123", "111111", "000000", "654321", "123123", "666666",
        "888888", "password1", "passw0rd", "P@ssw0rd", "secret", "test",
        "test123", "password123", "iloveyou", "dragon", "sunshine",
        "princess", "football",
    ]

    @classmethod
    def build_fallback_script(cls, path: str, extra_paths: Optional[list] = None) -> Optional[str]:
        """按附件内容（非题目描述）构造通用解题脚本。

        与旧版「按题库描述关键词选模板」不同，本版只嗅探附件本身的结构特征：
        - k = v 整数参数行 → RSA 系列（小指数 / Wiener / 共模，按参数存在性自动尝试）
        - 32/40/64 位 hex 串 → 常见弱口令哈希爆破
        - 纯字母密文（含 label: 前缀行）→ 凯撒 26 位移爆破 → 维吉尼亚频率分析
        - 长 base64/hex 串 → 多层循环解码
        任何分支只在结果中含 flag 时打印（防幻觉）；全部失败打印最接近的可读结果。

        多附件完整性（2026-08-21 攻坚修复）：path 为首附件，extra_paths 为其余附件
        （如 ezrsa 的 task.py 是脚本、output 才是参数——只嗅探 task.py 会漏掉 n/c）。
        所有附件内容拼接嗅探，参数可跨文件提取。
        """
        import os

        paths = [str(path)] + [str(p) for p in (extra_paths or []) if p]
        paths = [p for p in paths if p and os.path.exists(p)]
        if not paths:
            return None
        funcs = "\n".join(
            t for t in cls.attack_templates.values()
        )
        header = "paths = %r\nWORDS = %r\n" % (paths, cls.COMMON_WORDS)
        return funcs + "\n" + header + cls._TRIAGE_BODY

    # 通用嗅探主体（__PLACEHOLDER__ 由 build_fallback_script 替换；raw 串保留正则反斜杠）
    # 多附件支持：paths 为全部附件路径列表，逐一读取拼接后统一嗅探
    _TRIAGE_BODY = r'''
import re, hashlib

text = ""
for p in paths:
    try:
        with open(p, "rb") as f:
            text += f.read().decode("utf-8", errors="ignore") + "\n"
    except Exception:
        pass

def show(label, value):
    import re as _re
    s = str(value)
    if _re.search(r"(?i)(?:flag|ctf|dasctf)\{", s):
        print("[%s] %s" % (label, s))
        return True
    return False

# ── 1) 参数行嗅探: k = v（十进制/0x 十六进制，兼容 # 注释前缀与冒号分隔）→ RSA 系列攻击 ──
params = {}
for line in text.splitlines():
    s = line.strip()
    if s.startswith("#") or s.startswith("//"):
        s = s.lstrip("#/ \t")
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(0x[0-9a-fA-F]+|[0-9]+)\s*$", s)
    if m:
        try:
            params[m.group(1)] = int(m.group(2), 0)
        except ValueError:
            pass

# ── 裸数字行 RSA 嗅探（2026-08-21 攻坚修复）：output 是 print 裸数字行布局 ──
# ezrsa 类：6 行 [n1,c1,n2,c2,n3,c3] 或 7 行 [phi, n1,c1,n2,c2,n3,c3]（e<100 需爆破）
# ExcitingInverse 类：5 行 [e(短), phi, c, pinv, qinv]（已知 phi+逆元直接解密）
# ⚠️ 无条件执行：参数嗅探会被脚本代码污染（problem.py 的 nbits=1024/e=65537 会进 params），
#    不能依赖 if not params 判定（2026-08-21 实测：exciting_inverse 因此跳过嗅探）
_all_lines = [l.strip() for l in text.splitlines() if l.strip()]
# ── ExcitingInverse 布局（扫描式，2026-08-21 修复）：多附件拼接时第一行可能是
#    代码（problem.py），需在全文找「短数字(e) + 4 个大数(phi,c,pinv,qinv)」序列 ──
for _li in range(len(_all_lines) - 4):
    _l0 = _all_lines[_li]
    _cand = _all_lines[_li+1:_li+5]
    if not (_l0.isdigit() and 2 <= len(_l0) <= 20):
        continue
    _big4 = []
    for _l in _cand:
        if _l.isdigit() and len(_l) > 30:
            _big4.append(int(_l))
    if len(_big4) != 4:
        continue
    _pe, _pphi, _pc, _ppinv, _pqinv = int(_l0), _big4[0], _big4[1], _big4[2], _big4[3]
    try:
        from skills.rsa_fermat_factor import run as _rsa_run
        _m3 = _rsa_run({"n": 0, "e": _pe, "c": _pc, "phi": _pphi, "pinv": _ppinv, "qinv": _pqinv,
                        "attack": "phi_known_inv"})
        if not _m3:
            _m3 = _solve_phi_inv(_pe, _pphi, _pc, _ppinv, _pqinv)
        if _m3:
            _s3 = _m3.decode("utf-8", errors="ignore") if isinstance(_m3, bytes) else str(_m3)
            if "flag" in _s3.lower() or _s3.isprintable():
                print("[rsa_phi_known_inv] %s" % _s3)
                break
    except Exception:
        pass
# ezrsa 裸行嗅探（无条件执行：params 会被脚本代码污染，2026-08-21 修复）
_big_lines = []
for _l in _all_lines:
    if _l.isdigit() and len(_l) > 30:
        _big_lines.append(int(_l))
if len(_big_lines) >= 6:
        _idx = 1 if len(_big_lines) % 2 == 1 else 0  # 奇数行=含 phi 头
        _ns = _big_lines[_idx::2]
        _cs = _big_lines[_idx+1::2]
        if len(_ns) >= 2 and len(_cs) >= 2:
            try:
                from skills.rsa_fermat_factor import run as _rsa_run
                # 先试共享素数 GCD（多 n 有公因子时命中即秒解，2026-08-21 新增链）
                try:
                    _cf = _rsa_run({"e": 65537, "n1": _ns[0], "c1": _cs[0],
                                    "n2": _ns[1], "c2": _cs[1], "attack": "common_factor"})
                    if _cf:
                        _s0 = _cf.decode("utf-8", errors="ignore") if isinstance(_cf, bytes) else str(_cf)
                        if "flag" in _s0.lower() or _s0.isprintable():
                            print("[rsa_common_factor] %s" % _s0)
                except Exception:
                    pass
                # 广播攻击：e 从 3 开始爆破到 99（奇数），命中即出
                for _e in range(3, 100, 2):
                    _h2 = {"e": _e,
                           "n1": _ns[0], "c1": _cs[0],
                           "n2": _ns[1], "c2": _cs[1]}
                    if len(_ns) > 2:
                        _h2.update({"n3": _ns[2], "c3": _cs[2]})
                    if len(_ns) > 3:
                        _h2.update({"n4": _ns[3], "c4": _cs[3]})
                    if len(_ns) > 4:
                        _h2.update({"n5": _ns[4], "c5": _cs[4]})
                    try:
                        _m2 = _rsa_run(dict(_h2, attack="hastad"))
                    except Exception:
                        _m2 = None
                    if _m2:
                        _s2 = _m2.decode("utf-8", errors="ignore") if isinstance(_m2, bytes) else str(_m2)
                        if "flag" in _s2.lower() or _s2.isprintable():
                            print("[rsa_hastad_bruteforce_e%d] %s" % (_e, _s2))
                            break
            except Exception:
                pass

if params:
    n, e, c = params.get("n"), params.get("e"), params.get("c")
    # 场景补全：Hastad（只有 n1..n3/c1..c3 无 n/c）与共模（只有 e1/c1/e2/c2 无 e/c）
    # 都缺标准 n/e/c 三件套，需按附件结构判型后再进 RSA 分支（ezrsa/共模实测教训）。
    _has_hastad = bool(params.get("e") and params.get("n1") and params.get("c1")
                       and params.get("n2") and params.get("c2"))
    _has_cm = bool(params.get("n") and params.get("e1") and params.get("c1")
                   and params.get("e2") and params.get("c2"))
    if not (n and e and c) and _has_hastad:
        n, c = params["n1"], params["c1"]
    if (n and e and c) or _has_cm:
        # ── RSA 全套确定性攻击（P0-C 整改 2026-08-21）──
        # 优先复用 skills.rsa_fermat_factor（费马/phi_known/Hastad/共模/small_e/Wiener
        # 确定性脚本，不依赖 LLM 现场写攻击代码——实测 LLM 写 RSA 代码 0/2 全错）。
        # 显式按优先级逐个尝试（skill 自动检测会误判：e<=5 被 small_e 抢占后
        # 共模/Hastad 永不尝试——这里显式传 attack 逐个打，命中即停）。
        _rsa_ok = False
        try:
            from skills.rsa_fermat_factor import run as _rsa_run
            _attempts = []
            if params.get("d") and n and c:             # 已知私钥 d → 直接解密
                _attempts.append(("d_known", {"n": n, "e": e, "c": c, "d": params["d"]}))
            if params.get("phi"):                      # 已知 phi → 直接解密（ExcitingInverse 类）
                _attempts.append(("phi_known", {"n": n, "e": e, "c": c, "phi": params["phi"]}))
            if params.get("phi") and n and c:          # n+phi 都有 → phi 二次方程分解 p/q 兜底
                # 前置条件：invert(e,phi) 失败（gcd≠1）时 phi_known 必然返回 None，
                # phi_factor 先恢复 p/q，返回 p（供降幂/Rabin 后续），有 e/c 时直接解密。
                _attempts.append(("phi_factor", {"n": n, "e": e, "c": c, "phi": params["phi"]}))
            if params.get("n2") and params.get("c2"):  # 多组 (n,c) → 共享素数GCD / Hastad 广播（ezrsa 类）
                _h = {"n": n, "e": e, "c": c, "n1": n, "c1": c,
                      "n2": params["n2"], "c2": params["c2"]}
                if params.get("n3") and params.get("c3"):
                    _h.update({"n3": params["n3"], "c3": params["c3"]})
                _attempts.append(("common_factor", dict(_h)))
                _attempts.append(("hastad", _h))
            if _has_cm:  # 同 n 双公钥 → 共模攻击
                _attempts.append(("common_modulus", {"n": n, "e": e or params["e1"], "c": c or params["c1"],
                    "e1": params["e1"], "c1": params["c1"],
                    "e2": params["e2"], "c2": params["c2"]}))
            if e and c:
                _attempts.append(("auto", {"n": n, "e": e, "c": c}))  # small_e→wiener→费马 自动
            for _atk, _ap in _attempts:
                try:
                    _m = _rsa_run(dict(_ap, attack=_atk if _atk != "auto" else ""))
                except Exception:
                    _m = None
                if not _m:
                    continue
                _s = _m.decode("utf-8", errors="ignore") if isinstance(_m, bytes) else str(_m)
                if "flag" in _s.lower() or _s.isprintable():
                    print("[rsa_%s] %s" % (_atk, _s))
                    _rsa_ok = True
                    break
        except Exception:
            pass
        # skill 不可用时的内联兜底（small_e / wiener / 共模）
        if not _rsa_ok:
            if e and c:
                mm = small_e(c, e)
                if mm:
                    show("small_e", mm.to_bytes((mm.bit_length() + 7) // 8, "big").decode(errors="ignore"))
                mw = wiener_attack(n, e, c)
                if mw:
                    show("wiener", mw.to_bytes((mw.bit_length() + 7) // 8, "big").decode(errors="ignore"))
        if _has_cm:
            mc = common_modulus(params["c1"], params["c2"], params["e1"], params["e2"], params["n"])
            if mc:
                show("common_modulus", mc.to_bytes((mc.bit_length() + 7) // 8, "big").decode(errors="ignore"))

# ── 2) hex 哈希嗅探 → 弱口令爆破（仅常见口令字典）──
for m in re.finditer(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])|(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])|(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", text):
    target = m.group(0).lower()
    found = crack_hash(target, WORDS)
    if found:
        print("[hash_crack] flag{%s}" % found)

# ── 2.5) SimpleLegendre 二次剩余嗅探（玄盾杯真题：phi + N + [c...] 布局）──
# 扫描式：在多附件拼接文本中找「相邻两个 >100 位十进制行 + 后续 [大数列表]」模式
# ⚠️ 沙盒禁止 eval（2026-08-21 修复：用 ast.literal_eval 解析列表字面量）
import ast as _ast
_lines2 = text.splitlines()
for _i in range(len(_lines2) - 2):
    _a = _lines2[_i].strip()
    _b = _lines2[_i+1].strip()
    _c = _lines2[_i+2].strip()
    if (_a.isdigit() and _b.isdigit() and len(_a) > 100 and len(_b) > 100
            and (_c.startswith('[') or (len(_c) > 100 and _c.isdigit()))):
        _try_phi = int(_a)
        _try_N = int(_b)
        _rest = ' '.join(_lines2[_i+2:])
        _try_enc = None
        try:
            if _rest.strip().startswith('['):
                _try_enc = _ast.literal_eval(_rest.strip())
            elif _c.isdigit():
                _try_enc = _ast.literal_eval('[' + ','.join(_lines2[_i+2:]).replace('[', '').replace(']', ',') + ']')
        except Exception:
            _try_enc = None
        if _try_phi and _try_N and _try_enc and len(_try_enc) > 50:
            try:
                _lr = legendre_quadratic_residue(_try_phi, _try_N, _try_enc)
                if _lr and "flag" in _lr.lower():
                    print("[legendre_quadratic_residue] %s" % _lr)
            except Exception:
                pass
        break

# ── 2.6) LFSR 噪声混合嗅探（西湖论剑2021 FilterRandom 类）──
# 布局：mask1 行 + mask2 行（十进制 ~64bit）+ 2048 位 01 串（或含 '0'/'1' 长行）
_lfsr_masks = []
_lfsr_bits = ""
for _l in _all_lines:
    if _l.isdigit() and 1 <= len(_l) <= 20 and not _lfsr_bits:
        _lfsr_masks.append(int(_l))
    elif len(_l) >= 1024 and all(c in "01" for c in _l):
        _lfsr_bits = _l
if len(_lfsr_masks) >= 2 and len(_lfsr_bits) >= 1024:
    try:
        _lf = solve_lfsr_filter(_lfsr_masks[0], _lfsr_masks[1], _lfsr_bits)
        if _lf and ("flag" in _lf.lower() or "dasctf" in _lf.lower()):
            print("[lfsr_filter] %s" % _lf)
    except Exception:
        pass

# ── 3) 纯字母密文（兼容「密文: xxx」前缀行）→ 凯撒 / 维吉尼亚 ──
cipher_lines = []
for line in text.splitlines():
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    if ":" in s:
        head, _, rest = s.partition(":")
        if rest.strip() and not re.search(r"\d{6,}", head) and "=" not in head:
            s = rest.strip()
    cipher_lines.append(s)
cipher = " ".join(cipher_lines)
letters = [ch for ch in cipher if ch.isalpha()]
if len(letters) >= 8 and len(letters) / max(len(cipher), 1) > 0.5:
    pt, shift = caesar_bruteforce(cipher)
    if pt:
        show("caesar", pt)
    else:
        v = vigenere_crack(cipher)
        if v:
            show("vigenere", v)

# ── 4) 长 base64/hex 串 → 多层循环解码（跳过纯十进制大数参数）──
for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
    token = m.group(0)
    if not re.search(r"[A-Za-z]", token):
        continue
    dec = decode_multi_layer(token)
    if dec and dec != token:
        show("multilayer", dec)

# ── 5) key:/data: 格式 → Vigenère 解密（2026-08-21 安网杯 crypto1 模式）──
_km = re.search(r"key\s*[:：=]\s*(\S+)", text, re.I)
_dm = re.search(r"data\s*[:：=]\s*(\S+)", text, re.I)
if not (_km and _dm):
    # 八进制 ASCII 预解码后重试（crypto1: flag.txt 是八进制序列）
    # 2026-08-27 修复：\b[0-7]{3}\b 只匹配 3 位，漏 2 位冒号(72)等 token → key:/data: 匹配失败
    # 改 {2,3} 兼容 2-3 位八进制（如 ':' = 0o72 = '72'）
    _oct_chars = [chr(int(n, 8)) for n in re.findall(r"\b[0-7]{2,3}\b", text)]
    if len(_oct_chars) >= 20:
        _oct_text = "".join(_oct_chars)
        _km = re.search(r"key\s*[:：=]\s*(\S+)", _oct_text, re.I)
        _dm = re.search(r"data\s*[:：=]\s*(\S+)", _oct_text, re.I)
        if _km and _dm:
            text = _oct_text
if _km and _dm:
    try:
        _key, _ct = _km.group(1), _dm.group(1)
        _out = []
        _ki = 0
        for _ch in _ct:
            if _ch.isalpha():
                _b = ord("A") if _ch.isupper() else ord("a")
                _s = ord(_key[_ki % len(_key)].upper()) - ord("A")
                _out.append(chr((ord(_ch) - _b - _s) % 26 + _b))
                _ki += 1
            else:
                _out.append(_ch)
        _plain = "".join(_out)
        if "flag" in _plain.lower() or "dasctf" in _plain.lower():
            show("vigenere_key", _plain)
    except Exception:
        pass

# ── 6) A/B 字符序列 → 摩斯解码 + UUID 定位（2026-08-21 classicCrypto 模式）──
_ab = [c for c in text if c in "AB"]
if len(_ab) >= 100 and len(_ab) / max(len(re.sub(r"\s", "", text)), 1) > 0.6:
    _MORSE = {"-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G",
    "....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N",
    "---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U",
    "...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
    "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5",
    "-....":"6","--...":"7","---..":"8","----.":"9",
    ".-.-.-":".","--..--":",","..--..":"?","-.-.--":"!","-..-.":"/",
    "-.--.":"(","-.--.-":")",".-...":"&","---...":":","-.-.-.":";",
    "-...-":"=",".-.-.":"+","-....-":"-","..--.-":"_",".-..-.":'"',
    ".----.":"'","...-..-":"$",".--.-.":"@"}
    _groups = [g for g in re.split(r"\s+", text.strip()) if g and set(g) <= set("AB")]
    if _groups:
        for _dot_ch, _dash_ch in (("B", "A"), ("A", "B")):
            try:
                _dec = "".join(
                    _MORSE.get("".join("." if c == _dot_ch else "-" for c in g), "?")
                    for g in _groups)
            except Exception:
                continue
            if _dec.count("?") < len(_dec) * 0.3:
                _uuid = re.search(r"[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}", _dec)
                if _uuid:
                    # P1 修复（2026-08-21 classicCrypto 单表替换破解）：
                    # 原 show() 只在输出含 flag{ 时 print，单表替换密文（UUID 字母为密文）
                    # 不含 flag{ 被静默丢弃 → LLM 从零开始 stuck_loop。现用 hex 约束 +
                    # 频率匹配确定性破解：UUID 字母明文只能是 a-f（hex），按密文字母
                    # 全局频率 vs 英文 hex 字母频率贪心匹配，恢复映射后直出 flag。
                    _uuid_ct = _uuid.group(0)
                    try:
                        from collections import Counter as _Counter
                        _freq = _Counter(c for c in _dec.lower() if c.isalpha())
                        _total = max(sum(_freq.values()), 1)
                        _hex_eng = {"a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2}
                        _uuid_letters = sorted(
                            set(c.lower() for c in _uuid_ct if c.isalpha()),
                            key=lambda x: -_freq[x])
                        _used = set()
                        _sub = {}
                        for _c in _uuid_letters:
                            _cand = [(h, abs(_freq[_c] / _total * 100 - hf))
                                     for h, hf in _hex_eng.items() if h not in _used]
                            _cand.sort(key=lambda x: x[1])
                            _sub[_c] = _cand[0][0]
                            _used.add(_cand[0][0])
                        _uuid_pt = "".join(
                            _sub.get(c.lower(), c) if c.isalpha() else c for c in _uuid_ct)
                        print("[morse_ab_uuid] flag{%s}" % _uuid_pt)
                    except Exception:
                        # 破解失败兜底：至少输出解码结果 + UUID 定位供 LLM 参考
                        print("[morse_ab] %s" % _dec)
                        print("[morse_ab_uuid_raw] %s" % _uuid_ct)
                break
'''

    # 高频考点清单（供主 Agent 定位攻击方向）
    checkpoints: list = [
        "RSA: 共模攻击 / 小指数 / n 分解（factordb）/ 共享素数 GCD / Wiener 攻击",
        "AES: ECB 块特征（相同明文块相同密文块）/ CBC 字节翻转 / padding oracle",
        "古典: 凯撒 / Vigenère / 栅栏 / 培根 / 摩斯",
        "编码: base64/32/16 / hex / url / rot13 / Brainfuck",
        "哈希: MD5/SHA 弱密码爆破 / 长度扩展攻击",
    ]

    def suggest_steps(self, description: str, attachments: Optional[list] = None) -> list[str]:
        """按题目描述给出初始攻击步骤。"""
        desc = (description or "").lower()
        steps = ["先用 CyberChef/工具识别编码或加密特征（标志头、长度、字符集）"]
        if any(k in desc for k in ("rsa", "公钥", "n=", "e=", "c=")):
            steps += ["提取 n/e/c，尝试共模攻击（若多组公钥）或小指数攻击"]
        if any(k in desc for k in ("aes", "ecb", "分组")):
            steps += ["检查 ECB 模式块特征（相同前缀块），利用块独立性分析"]
        if any(k in desc for k in ("凯撒", "caesar", "移位", "vigenere")):
            steps += ["尝试凯撒暴力破解 26 种位移"]
        if any(k in desc for k in ("base64", "编码", "hex", "url", "多层")):
            steps += ["尝试多层解码（base64/hex/url 循环）"]
        if any(k in desc for k in ("hash", "哈希", "md5", "sha", "爆破", "密码")):
            steps += ["识别哈希类型，用弱密码字典爆破"]
        if not any(k in desc for k in ("rsa", "aes", "凯撒", "caesar", "base64", "hash", "哈希", "md5")):
            steps.append("先看附件/描述中的特征字符串，判断编码或算法类型")
        return steps


def _inline_multilayer_decode(s: str) -> str:
    """可靠的多层编码解码（base64/32/16 循环 + ROT13 收尾）。

    替代有 bug 的 base64_multilayer：每层解码后校验可读性，解出 synt{（ROT13 的
    flag{）时自动 ROT13——玄盾杯 ezmult 类题（base64+ROT13）1 次直出 flag。
    """
    import base64
    import binascii

    text = str(s).strip()

    def _rot13(t: str) -> str:
        out = []
        for ch in t:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                out.append(chr((ord(ch) - base + 13) % 26 + base))
            else:
                out.append(ch)
        return "".join(out)

    def _printable(t: str) -> bool:
        return bool(t) and all(c.isprintable() or c in "\n\r\t" for c in t)

    for _ in range(10):
        low = text.lower()
        if "flag{" in low or "dasctf{" in low:
            return text
        if text.startswith("synt{"):
            return _rot13(text)  # ROT13 的 flag{ 前缀 → 还原
        nxt = None
        # base64
        try:
            b = base64.b64decode(text + "=" * ((4 - len(text) % 4) % 4))
            cand = b.decode("utf-8", errors="replace")
            if _printable(cand) and cand != text:
                nxt = cand
        except Exception:
            pass
        # base32
        if nxt is None:
            try:
                b = base64.b32decode(text.upper() + "=" * ((8 - len(text) % 8) % 8))
                cand = b.decode("utf-8", errors="replace")
                if _printable(cand) and cand != text:
                    nxt = cand
            except Exception:
                pass
        # hex
        if nxt is None:
            try:
                b = binascii.unhexlify(text)
                cand = b.decode("utf-8", errors="replace")
                if _printable(cand) and cand != text:
                    nxt = cand
            except Exception:
                pass
        if nxt is None:
            break
        text = nxt
    low = text.lower()
    if "flag{" in low:
        return text
    if text.startswith("synt{"):
        return _rot13(text)
    return text


def _reverse_static_analyze(path: str) -> dict:
    """reverse 静态特征指纹（锐评：静态特征匹配+快速失败——40%→70%）。

    自动识别：文件类型（ELF/PE/pyc/JS）→ UPX 加壳 → strings 扫 flag →
    .data 段目标字符串（省赛 reverse_2 经验）→ 输出结构化结果供 LLM 直用。
    """
    import os
    import re

    if not path or not os.path.exists(path):
        return {"ok": False, "error": "文件不存在"}
    data = open(path, "rb").read()
    result = {"ok": True, "path": path, "size": len(data)}

    # 1. 类型识别
    if data[:4] == b"\x7fELF":
        result["kind"] = "elf"
    elif data[:2] == b"MZ":
        result["kind"] = "pe"
    elif data[:4] in (b"\xca\xf0\xfe\xd0",):
        result["kind"] = "pyc"
    elif path.endswith((".js", ".html", ".htm")):
        result["kind"] = "js"
    else:
        result["kind"] = "unknown"

    # 2. UPX 加壳检测
    result["upx"] = bool(b"UPX!" in data or b"UPX0" in data[:3000])

    # 3. strings 扫 flag（含常见 flag 前缀）
    strs = [s.decode("utf-8", errors="replace")
            for s in re.findall(rb"[\x20-\x7e]{5,}", data)]
    flags = [s for s in strs if re.search(
        r"(?:flag|ctf|DASCTF|UNCTF)\{[^}\s]{3,}", s, re.I)]
    result["flags"] = list(dict.fromkeys(flags))

    # 4. .data 段目标字符串（省赛 reverse_2 经验：目标可能在 .data 非 .rodata）
    if result["kind"] in ("elf", "pe"):
        data_hints = [s for s in strs if "{" in s and len(s) < 40 and not s.startswith("$")]
        result["data_hints"] = data_hints[:5]

    # 5. 关键 API/提示（strcmp/printf/input 等）
    key_apis = [s for s in strs if re.search(
        r"(strcmp|scanf|printf|gets|input|check|verify|flag|恭喜|正确|Wrong)", s, re.I)][:6]
    result["key_strings"] = key_apis
    return result


def _caesar_bruteforce(cipher: str) -> dict:
    """凯撒暴力破解（模板直出——crypto 基础题高频，正式赛简单题基本盘）。

    尝试 26 个位移，含 flag{ 前缀的明文即为解（支持大小写/非字母保留）。
    """
    import re

    text = str(cipher)
    for shift in range(26):
        plain = "".join(
            chr((ord(c) - 97 + shift) % 26 + 97) if c.islower()
            else (chr((ord(c) - 65 + shift) % 26 + 65) if c.isupper() else c)
            for c in text
        )
        m = re.search(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", plain)
        if m:
            # P0-3 实测修复（2026-08-21）：此前 return {"flag": plain} 返回整段解密
            # 明文（含"密文: "前缀、注释行、\r\n），导致 fast_solve 命中的 flag 带垃圾
            # 后缀，被上游答案校验拦截丢弃。现在只返回正则提取出的干净 flag{...}。
            return {"ok": True, "flag": m.group(0), "shift": shift,
                    "method": "caesar_bruteforce", "plaintext": plain}
    return {"ok": False, "note": "26 位移均无 flag 前缀——可能非凯撒或需其他处理"}




def _bacon_decode(seq: str) -> dict:
    """培根密码解码（A/B 序列 → 明文——强网杯 classicCrypto 题型覆盖，覆盖面扩展）。

    A/B 5 位一组 → 二进制 → 字母（A=0/B=1）。经典培根 24 字母表简化 26 字母。
    """
    import re

    s = re.sub(r"[^AB]", "", str(seq).upper())
    if not s or len(s) % 5 != 0:
        return {"ok": False, "note": "非纯 A/B 序列或长度非 5 倍数"}
    table = "abcdefghijklmnopqrstuvwxyz"
    out = []
    for i in range(0, len(s), 5):
        code = int(s[i:i + 5].replace("A", "0").replace("B", "1"), 2)
        out.append(table[code] if code < 26 else "?")
    text = "".join(out)
    flags = re.findall(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", text)
    return {"ok": True, "flag": text, "flags": flags, "method": "bacon_decode"}


def fast_solve(kind: str = "", **params) -> dict:
    """crypto 高频题型一键直出（识别题型即出答案，减少 LLM 轮次——提速二）。

    支持题型: fermat/rsa（费马分解）、zip（zip 链解码）、ecb/aes（AES-ECB 块攻击）、
              lattice/lll（格攻击）、b64/multilayer（多层编码解码）。
    模型识别题型后 1 次调用即出答案，避免多轮 reason 往返。
    """
    kind = (kind or "").lower()
    try:
        if kind in ("fermat", "rsa", "费马"):
            from skills.rsa_fermat_factor import run as _fermat
            return _fermat(params)
        if kind in ("zip", "压缩"):
            # 2026-08-22 疯狂刷题 8% 后补：伪加密破解优先（55 题大量 zip 主类型）
            from skills.zip_fake_encryption import run as _zip_fake_run
            try:
                _r = _zip_fake_run(params)
                if _r.get("ok"):
                    return _r
            except Exception:  # noqa: BLE001
                pass
            from skills.zip_filename_chain_decode import zip_filename_chain_decode
            return zip_filename_chain_decode(params)
        if kind in ("ecb", "aes", "aes-ecb"):
            from skills.crypto_ecb_block_attack import crypto_ecb_block_attack
            return crypto_ecb_block_attack(params)
        if kind in ("lattice", "lll", "格"):
            from skills.crypto_lattice_attack import crypto_lattice_attack
            return crypto_lattice_attack(params)
        if kind in ("b64", "base64", "multilayer", "多层"):
            return {"ok": True, "flag": _inline_multilayer_decode(str(params.get("s", "")))}
        if kind in ("caesar", "凯撒", "shift", "凯撒密码"):
            return _caesar_bruteforce(str(params.get("s", "")))
        if kind in ("bacon", "培根", "ab序列", "A/B"):
            return _bacon_decode(str(params.get("s", "")))
        if kind in ("vigenere", "维吉尼亚"):
            r = vigenere_crack(str(params.get("s", "")))
            return {"ok": bool(r), "flag": r, "method": "vigenere_crack"}
        if kind in ("common_modulus", "共模", "c_mod"):
            # 内联共模攻击（common_modulus 是 attack_templates 字符串模板非真实函数——
            # 同 decode_multi_layer/crack_hash 教训：不依赖不存在的模块函数）
            import math

            c1 = int(params["c1"]); c2 = int(params["c2"])
            e1 = int(params["e1"]); e2 = int(params["e2"]); n = int(params["n"])
            g, x, y = math.gcd(e1, e2), 0, 0  # 扩展欧几里得求 a*e1+b*e2=1
            def _egcd(a, b):
                if b == 0:
                    return a, 1, 0
                g_, x_, y_ = _egcd(b, a % b)
                return g_, y_, x_ - (a // b) * y_
            g, a, b = _egcd(e1, e2)
            if g != 1:
                return {"ok": False, "note": f"gcd(e1,e2)={g} != 1，共模不适用"}
            m = (pow(c1, a, n) * pow(c2, b, n)) % n
            return {"ok": True, "flag": str(m), "method": "common_modulus_inline"}
        if kind in ("small_e", "小指数", "low_e"):
            # 内联小指数明文攻击（small_e 是 attack_templates 字符串模板非真实函数——
            # 同 decode_multi_layer/crack_hash/common_modulus 教训）
            c = int(params["c"]); e = int(params["e"])
            # e 次方根（整数开方——m^e < n 时直接开方得明文）
            lo, hi = 0, c
            while lo <= hi:
                mid = (lo + hi) // 2
                v = mid ** e
                if v == c:
                    return {"ok": True, "flag": str(mid), "method": "small_e_inline"}
                if v < c:
                    lo = mid + 1
                else:
                    hi = mid - 1
            return {"ok": False, "note": "非整数 e 次方根——可能需其他小指数攻击"}
        if kind in ("wiener", "wiener攻击"):
            return {"ok": True, "flag": wiener_attack(
                int(params["n"]), int(params["e"]), int(params["c"])),
                "method": "wiener_attack"}
        if kind in ("hash", "哈希", "hash_crack"):
            # 内联哈希爆破（crack_hash 是 attack_templates 字符串模板非真实函数——
            # 同 decode_multi_layer 教训：不依赖不存在的模块函数）
            # P1 修复（2026-08-21 实战演练）：run.py 调 fast_solve("hash", s=附件内容)，
            # 但此分支只读 params["target"]（哈希值）——契约不匹配导致 hash_brute
            # 确定性链空转→LLM 幻觉。现改为：target 显式优先，否则从 s 提取
            # 32/40/64 位 hex；words 用完整 COMMON_WORDS（非 8 词硬编码）。
            import hashlib as _hashlib
            import re as _re

            words = params.get("words") or CryptoToolkit.COMMON_WORDS
            target = str(params.get("target", "")).strip().lower()
            if not target:
                s = str(params.get("s", "") or "")
                _m = _re.search(
                    r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])|"
                    r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])|"
                    r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])",
                    s, _re.I)
                if _m:
                    target = _m.group(0).lower()
            if not target:
                return {"ok": False, "note": "未找到哈希值（target/s 均无 32/40/64 hex）"}
            for w in words:
                if (_hashlib.md5(w.encode()).hexdigest() == target
                        or _hashlib.sha1(w.encode()).hexdigest() == target
                        or _hashlib.sha256(w.encode()).hexdigest() == target):
                    # 题目约定 flag 格式为 flag{明文}
                    return {"ok": True, "flag": f"flag{{{w}}}", "method": "hash_crack",
                            "plaintext": w}
            return {"ok": False, "note": "弱密码字典未命中——需更大字典"}
        if kind in ("morse", "摩斯", "摩斯电码"):
            # 摩斯电码解码（. - 点划 → 字母——高频 misc 题型秒解）
            code = {".": "E", "-": "T", ".-": "A", "-...": "B", "-.-.": "C",
                    "-..": "D", "..": "I", "--.": "G", "....": "H", ".---": "J",
                    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
                    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "..-": "U",
                    "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z"}
            import re
            s = str(params.get("s", ""))
            out = []
            for tok in re.split(r"[ /]+", s.strip()):
                out.append(code.get(tok, ""))
            text = "".join(out)
            flags = re.findall(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", text.lower())
            return {"ok": bool(text), "flag": text, "flags": flags, "method": "morse_decode"}
        if kind in ("rsa_pq", "已知pq", "rsa_pq"):
            # RSA 已知 p/q 解密（p,q,e,c → m——高频 RSA 变种秒解）
            from Crypto.Util.number import inverse
            p, q, e, c = (int(params[k]) for k in ("p", "q", "e", "c"))
            d = inverse(e, (p - 1) * (q - 1))
            m = pow(c, d, p * q)
            from Crypto.Util.number import long_to_bytes
            text = long_to_bytes(m).decode("utf-8", errors="ignore")
            return {"ok": True, "flag": text, "method": "rsa_pq_decrypt"}
        if kind in ("traffic", "流量", "pcap", "pcapng"):
            # 流量分析快速直出：pcap/pcapng → ASCII 字符串提取 → flag 扫描
            # （flag 常在流量载荷的可读字符串里——秒解，misc 高频）
            try:
                from skills.misc_traffic_analysis import _parse_pcap_packets, _parse_pcapng_packets
                import re
                path = str(params.get("path", ""))
                with open(path, "rb") as f:
                    magic = f.read(4)
                if magic == b"\x0a\x0d\x0d\x0a":
                    pkts = _parse_pcapng_packets(path)
                else:
                    pkts = _parse_pcap_packets(path)
                all_data = b"".join(d for _, d in pkts)
                strs = [s.decode("utf-8", errors="replace")
                        for s in re.findall(rb"[ -~]{6,}", all_data)]
                flags = [s for s in strs if re.search(
                    r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", s, re.I)]
                return {"ok": bool(flags), "flags": list(dict.fromkeys(flags))[:5],
                        "packets": len(pkts), "method": "traffic_ascii_scan"}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"流量解析失败: {exc}"}
        if kind in ("web", "xxe", "ssti", "upload", "sql"):
            # Web 攻击路径模板（描述特征→攻击指引——正式赛 web 盲区攻坚，
            # 命中即用——2026-08-21 不惜代价攻坚）
            desc = str(params.get("desc", "")).lower()
            guides = {
                "xxe": ("XXE：SVG/XML 上传 → 外部实体读 /flag——payload: "
                        "<!DOCTYPE x [<!ENTITY f SYSTEM 'file:///flag'>]><x>&f;</x>", "web_xxe_file_read"),
                "ssti": ("SSTI：模板注入 → {{7*7}} 探测 → {{config}}/{{''.__class__}} 链 RCE——", "ssti_detect"),
                "upload": ("上传绕过：先试 .php 直传 → 双扩展/大小写/空字节 → webshell 连接——", "web_upload_bypass"),
                "sql": ("SQL 注入：' OR 1=1--+ 绕过登录 → UNION 注入读库——", "web_sqli"),
            }
            for kw, (guide, skill) in guides.items():
                if kw in desc:
                    return {"ok": True, "guide": guide, "skill": skill,
                            "method": f"web_{kw}_guide"}
            return {"ok": False, "note": "无已知 web 特征——需靶机实测（web 盲区）"}
        if kind in ("reverse", "upx", "static", "静态", "strings"):
            return _reverse_static_analyze(str(params.get("path", "")))
        if kind in ("xor", "异或", "单字节异或"):
            # 单字节 XOR 爆破：hex 密文 → 0-255 key → 找 flag
            import re
            s = str(params.get("s", ""))
            data = None
            for h in re.findall(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{4,}", s):
                h2 = h[2:] if h.lower().startswith("0x") else h
                if len(h2) % 2 == 0:
                    try:
                        data = bytes.fromhex(h2)
                        break
                    except Exception:
                        pass
            if data is None:
                try:
                    data = bytes.fromhex(s.strip())
                except Exception:
                    return {"ok": False, "note": "未找到 hex 密文"}
            for k in range(256):
                out = bytes(b ^ k for b in data)
                m = re.search(rb"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", out)
                if m:
                    return {"ok": True, "flag": m.group(0).decode(), "method": f"xor_key_{k}"}
            return {"ok": False, "note": "单字节 XOR 未命中 flag"}
        if kind in ("rail", "railfence", "栅栏", "fence", "rail_fence"):
            # 栅栏密码（Rail Fence）：2-11 轨解密，找 flag
            import re
            def _rail_decrypt(ct, rails):
                fence = [[None] * len(ct) for _ in range(rails)]
                rail, step = 0, 1
                for i in range(len(ct)):
                    fence[rail][i] = '*'
                    if rail == 0:
                        step = 1
                    elif rail == rails - 1:
                        step = -1
                    rail += step
                idx = 0
                for r in range(rails):
                    for i in range(len(ct)):
                        if fence[r][i] == '*' and idx < len(ct):
                            fence[r][i] = ct[idx]
                            idx += 1
                rail, step, out = 0, 1, []
                for i in range(len(ct)):
                    out.append(fence[rail][i])
                    if rail == 0:
                        step = 1
                    elif rail == rails - 1:
                        step = -1
                    rail += step
                return ''.join(out)
            s = str(params.get("s", "")).strip()
            for rails in range(2, 12):
                pt = _rail_decrypt(s, rails)
                m = re.search(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", pt)
                if m:
                    return {"ok": True, "flag": m.group(0), "method": f"rail_{rails}"}
            return {"ok": False, "note": "栅栏密码未命中（试 2-11 轨）"}
        if kind in ("affine", "仿射", "仿射密码"):
            # 仿射密码：a∈{与26互质} b∈0-25 爆破
            import re
            def _affine_decrypt(ct, a, b):
                ainv = pow(a, -1, 26)
                out = []
                for c in ct:
                    if c.isalpha():
                        base = ord('A') if c.isupper() else ord('a')
                        out.append(chr((ainv * (ord(c) - base - b)) % 26 + base))
                    else:
                        out.append(c)
                return ''.join(out)
            s = str(params.get("s", "")).strip()
            for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
                for b in range(26):
                    pt = _affine_decrypt(s, a, b)
                    if "flag" in pt.lower() or "ctf{" in pt.lower():
                        m = re.search(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", pt)
                        return {"ok": True, "flag": m.group(0) if m else pt,
                                "method": f"affine_a{a}_b{b}"}
            return {"ok": False, "note": "仿射密码未命中"}
        if kind in ("brainfuck", "bf", "ook", "brainfk", "脑洞"):
            # Brainfuck 解释器：执行代码 → 输出文本 → 找 flag
            import re
            s = str(params.get("s", ""))
            code = ''.join(c for c in s if c in "><+-.,[]")
            if not code or '[' not in code or ']' not in code:
                return {"ok": False, "note": "非 Brainfuck 代码（缺 [] 指令）"}
            match = {}
            stack = []
            for pos, c in enumerate(code):
                if c == '[':
                    stack.append(pos)
                elif c == ']':
                    if stack:
                        j = stack.pop()
                        match[j], match[pos] = pos, j
            tape = [0] * 30000
            ptr, out, i = 0, [], 0
            while i < len(code):
                c = code[i]
                if c == '>':
                    ptr += 1
                elif c == '<':
                    ptr -= 1
                elif c == '+':
                    tape[ptr] = (tape[ptr] + 1) % 256
                elif c == '-':
                    tape[ptr] = (tape[ptr] - 1) % 256
                elif c == '.':
                    out.append(chr(tape[ptr]))
                elif c == '[' and tape[ptr] == 0:
                    i = match.get(i, i)
                elif c == ']' and tape[ptr] != 0:
                    i = match.get(i, i)
                i += 1
                if len(out) > 100000:
                    break
            text = ''.join(out)
            m = re.search(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", text)
            if m:
                return {"ok": True, "flag": m.group(0), "method": "brainfuck"}
            return {"ok": bool(text), "flag": text, "method": "brainfuck"}
        if kind in ("base58", "base62", "比特币", "btc"):
            # Base58/Base62 解码（比特币地址/短链接类高频题型）
            import re
            s = str(params.get("s", "")).strip()
            if not s:
                return {"ok": False, "note": "空输入"}
            # 提取候选串（连续 Base58/Base62 字符）
            cands = re.findall(r"[1-9A-HJ-NP-Za-km-z]{4,}", s)
            out_texts = []
            for c in cands:
                try:
                    if set(c) <= set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"):
                        out_texts.append(("base58", _b58_decode(c)))
                    else:
                        out_texts.append(("base62", _b62_decode(c)))
                except Exception:
                    pass
            for method, txt in out_texts:
                m = re.search(r"(?:flag|ctf|DASCTF)\{[^}\s]{3,}\}", txt, re.I)
                if m:
                    return {"ok": True, "flag": m.group(0), "method": method}
            if out_texts:
                return {"ok": True, "flag": out_texts[0][1], "method": out_texts[0][0]}
            return {"ok": False, "note": "未识别 Base58/Base62 串"}
    except Exception as exc:  # noqa: BLE001 - 直出失败降级给主流程
        return {"ok": False, "error": f"{kind} 直出失败: {type(exc).__name__} {exc}"}
    return {"ok": False, "error": f"未知题型 {kind}，支持: fermat/rsa/zip/ecb/lattice/b64/xor/rail/affine/brainfuck/base58"}


def _b58_decode(s: str) -> str:
    """Base58 解码（比特币字母表），返回解码后的文本（errors 容错）。"""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for c in s:
        num = num * 58 + alphabet.index(c)
    # 前导 '1' 补零字节
    n_pad = len(s) - len(s.lstrip("1"))
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return (b"\x00" * n_pad + raw).decode("utf-8", errors="ignore")


def _b62_decode(s: str) -> str:
    """Base62 解码，返回解码后的文本。"""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    num = 0
    for c in s:
        num = num * 62 + alphabet.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return raw.decode("utf-8", errors="ignore")
