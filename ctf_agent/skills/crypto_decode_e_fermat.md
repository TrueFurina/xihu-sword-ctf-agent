# skill: crypto_decode_e_fermat（10696 解出链——可复用）

> 沉淀自：10696 TheoremPlus（2026-08-23 离线推导解出——未平台验证——诚实口径）
> 场景：RSA 题——e 由自定义 decode_e 递归函数生成（威尔逊定理相关）+ p/q 相邻（费马分解秒解）

## 适用特征
- task.py 含 decode_e 递归函数（威尔逊调整：`if e - mul % e - 1 == 0: mulmod = mul % e - e else: mulmod = mul % e`——递归求和）
- p = next_prime(q)（**p/q 相邻**——费马分解秒解）
- n/e/c 参数完整（**自动提取防手抄错**——c 手抄错导致 m 乱码的教训）

## 解出链（5 步）
```
1. 自动提取参数：task.py 中 re 提取 n/e/c（防手抄——c 错→m 乱码教训）
2. 费马分解：p/q 相邻——a=isqrt(n)+1 起——b²=a²-n 平方数即分解（0.0s）
3. decode_e 精确：decode_e(e) = -π(e) + 2
   ——素数贡献 -1（威尔逊：(k-1)!≡-1 mod k）；合数贡献 0（(k-1)!≡0 mod k）；
   唯一例外 4=2²（3! mod 4 = 2——贡献 +2）
   ——用 sympy.primepi(e) 秒算 π——e = abs(decode_e(输入)) = π(输入) - 2
4. gcd 判断：g = gcd(e, phi)——g==1 直接标准解密 m = c^d（pow(c, inverse(e,phi), n)）
   ——10696 的 e=36421873 与 phi 互素（g=1——不需要开根）
5. m → long_to_bytes → flag
```

## 关键代码（核心 3 行）
```python
from sympy import primepi
from math import gcd
a = isqrt(n) + 1  # 费马：b² = a²-n 平方数 → p,q = a-b, a+b
e = primepi(E_INPUT) - 2  # decode_e = -π + 2（4=2² 唯一非零贡献）
m = pow(c, inverse(e, (p-1)*(q-1)), n) if gcd(e, phi) == 1 else None
```

## 验证（真实解出记录）
- 10696 TheoremPlus：flag = DASCTF{Ot2N63D_n8L6kJt_f40V61m_zS1O8L7}——离线推导解出（未平台验证——accepted=0）——c 值修正（完整 616 位自动提取——之前手抄 618 位错）

## 失败模式
- c 手抄错 → m 乱码（必须自动提取——10696 教训）
- decode_e 假设 -π（不含 +2）→ e 差 2 → m 乱码（必须素数幂分析确认 4=2² 贡献）
- gcd(e,phi) > 1 → 需开根（见 crypto_custom_e_hint_bfs_root——BFS 开根）
