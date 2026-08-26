# skill: crypto_custom_e_hint_bfs_root（10733 解出链——可复用）

> 沉淀自：10733_How_many_rot（CRYPTO-02——2026-08-23 离线推导解出——未平台验证——诚实口径）
> 场景：RSA 题——e 为 2 的幂（65536 等）+ hint 给出 W 相关值（题目用 hint 帮助分解 n）——需 BFS 开根 + ROT 检测

## 适用特征
- n/e/c 参数完整（task.py/脚本注释——**必须自动提取防手抄错**）
- e = 2^16（65536 等 2 的幂）——gcd(e, phi) 非 1（不能直接标准解密）
- hint 存在（hint 与 n 的关系：W = pow(e, n, n)——p = gcd(W² - hint, n)）

## 解出链（5 步）
```
1. 自动提取参数：task.py 中 re 提取 n/e/c/hint（不要手抄——10696 教训）
2. hint 解 p：W = pow(e, n, n) —— p = gcd(W*W - hint, n)（isPrime 验证 n%p==0）
3. gcd 判断：g = gcd(e, phi) —— g==1 直接标准解密 m=c^d；
   g>1 且 e 为 2 的幂（e=2^k）→ 对 c 开 2^k 次方根
4. BFS 开根：模 p/q 反复开平方（p%4==3 时 sqrt = pow(x, (p+1)//4, p)，含 ± 候选）——
   16 层平方根（e=2^16）——p/q 侧候选——CRT 组合得 m
5. ROT 检测：m 可能为 ROT13 编码的 DASCTF（题名含 rot 提示）——
   m.translate(rot13) 检查 DASCTF{/flag{/CTF——QNFPGS{ = ROT13 的 DASCTF{
```

## 关键代码（核心 5 行）
```python
from math import gcd
W = pow(e, n, n)
p = gcd(W*W - hint, n)                      # hint 解 p（W/gcd 法）
# 开根：sqrt_mod(a, p) = pow(a, (p+1)//4, p) 当 p%4==3 且 a 是二次剩余
# BFS 16 层（e=2^16）→ p/q 候选 → CRT 组合 → ROT13 检查（QNFPGS{→DASCTF{）
```

## 验证（真实解出记录）
- 10733 How_many_rot：flag（ROT13 编码 QNFPGS{...}——解码 DASCTF{<redacted>}）——离线推导解出（未平台验证——accepted=0）

## 失败模式
- c 手抄错 → m 乱码（必须自动提取——10696 教训）
- p%4 != 3 → sqrt_mod 需其他方法（Tonelli-Shanks）
- e 非 2 的幂（g>1 非 2^k）→ 需通用 AMM（Adleman-Manders-Miller）
