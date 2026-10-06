# 曲线25519 ECXOR 能力接通
### questions_ext 大池离线分诊：CSAW-Finals 2017 ECXOR 确定性攻破

> 生成时间：2026-10-07　范围：`ctf_agent/`　成本：**¥0**（纯离线、零 LLM 调用）
> 提交：`e06aabd`（实现）+ `b3d8581`（测试）→ 本文（文档）
> 口径声明：本文所述均为 **presolve（确定性攻击链）命中**，**不计入「LLM 自主解题率」**。

---

## 0. 一句话结论

外部大池 `questions_ext`（34 题、全带真值）的 crypto 候选中，**ECXOR 可被确定性离线攻破**。
根因仍是老问题——**不是缺能力，是「能力不可达」**：曲线25519 的点运算本身毫无难度，
但没有任何一条确定性链能识别「`;` 分隔的 32 字节压缩点密文」这一格局，
更没有「用小字节密钥逐 residue 复原 + 英文似然消歧」的求解器。
新增 `_try_ecxor` 后，该题在本机纯 Python（无 pycryptodome 依赖亦可，自足 RFC8032 算术）**0.4s 内命中真 flag**，
与题面 `flag_sha256` 逐字吻合。

---

## 1. `questions_ext` 池 crypto 候选现状

| 题目 | 赛事 | 附件 | 状态 | 关键特征 |
|---|---|---|---|---|
| almost_xor | CSAW-Quals 2017 | 2 | ✅ 上轮攻破 | n-bit 分组模加 |
| **ecxor** | **CSAW-Finals 2017** | **3** | ✅ **本轮攻破** | **曲线25519 点加 + 小字节密钥** |
| collusion | CSAW-Quals 2018 | 4 | ⬜ 未破 | RSA-IBE 串谋攻击（纯数论，见 §6） |
| des2bites | CSAW-Quals 2019 | 2 | ⬜ 未破 | DES 弱密钥（密文为纯十进制串，编码待解，见 §6） |
| m_ster_0f_prn9 | CSAW-Finals 2022 | 1 | ❌ 本机不可行 | 截断 LCG，需格基约简（fpylll/Sage 本机无） |

> 其余候选（lowe/babycrypto/another_xor/br3akth3vau1t）属 A5 池，已在前两轮攻破，不重复计。

---

## 2. 攻破细节：ECXOR（CSAW-Finals 2017）

### 2.1 密文格局

`ciphertext`（11610 B）= 258 个 base64 令牌以 `;` 连接，每段解出恰 **32 字节** →
Curve25519 **压缩点**。官方 `ecxor_handout_100.py` + `rfc8032.py` 给出语义：

```python
KEYLEN = 12
topoint = lambda n: point_mul(n, G)
encrypt(key, ptxt):
    points = [ point_add(topoint(x), topoint(ord(y)))
               for (x, y) in zip(cycle(key), ptxt) ]
    return b';'.join(base64.b64encode(point_compress(p)) for p in points)
```

即 `ct[i] = ( key[i mod L] + ord(pt[i]) ) · G`，`key` 为 `os.urandom(12)`（每字节 0..255）。

### 2.2 为什么「能力不可达」

- 点加/倍点/压缩在 `rfc8032.py` 里现成，**难度为零**；
- 但 presolve 既有 ~30 路 handler 无一识别「压缩点串」格局，triage 段也只做 hex/url/base64 往返；
- 密钥为 **12 个随机字节**，穷举 `2^96` 不可行；直接 `frompoint` 又只解 `range(256)`，
  而 `key[i]+ord ≥ 256` 极常见 → 朴素「解点」失败。

⇒ 典型「**能力存在但不可达**」：缺的是格局识别 + 正确的代数切入角度。

### 2.3 求解链（差分 + 英文似然）

关键观察：**相对字符偏移与绝对密钥无关**。对同一 residue（`i ≡ j mod L`），以首个点为锚：

```
ct[i] - ct[j] = (ord_i - ord_j) · G        （key 抵消）
```

- `ord_i ≥ ord_j`：标量落在 `[0,126] ⊆ [0,255]` → `frompoint(ct[i]-ct[j])` 直接得 `ord_i-ord_j`；
- `ord_i < ord_j`：取 `ct[j]-ct[i]` 得正标量，取负即偏移。

于是每个 residue 的可解析性**恒成立**（不再受 `key[i]+ord ≥ 256` 影响），得到一组相对偏移 `Δ`。
剩下只需确定每 residue 的「锚字符」基值 `b`：`cat_i = b + Δ_i`。用**英文单字符对数似然**
（空格最高频）在 `b ∈ [0,255]` 中搜索即得。

```
残差细节（本轮踩坑）：似然**不得折叠大小写**——位移 ±32 会把小写↔大写
（a↔A 相差 32），折叠后两解并列，会误选 base=76 得到 `fLag{sYnth_…`。
修法：大写字母降权 ×0.03（英文小写占绝对多数），并列即破。
```

### 2.4 实测

```
L = 12
key = b'\xee\xb7\xca\xc7u\xaa\xf6\xf8\xa5e\x9e#'
明文首行 = flag{generalizing_vignere_to_arbitrary_groups_is_not_good}"If you're going to turn into a pig, my dear," said Alice, ...
sha256(flag) = 0e063f15a4c24ca6e9d9277225fdf5f8ff7b9ea61d66e0a111eae4919d6a489f
题面 flag_sha256 = 0e063f15…489f   ✅ 逐字吻合
```

明文为《爱丽丝梦游仙境》散文 + 前置 flag，全链路可复现。

---

## 3. 改动

**实现** `core/presolve.py`（+~230）：
- 新增 `_try_ecxor(question)`，两道门控——① 曲线指纹（附件含 `point_add`+`point_mul`，或题面点名 `curve25519/x25519/25519`）；
  ② 结构指纹（`;` 分隔、每段 base64 解出恰 32 字节）。
- 内联**自足** Curve25519（RFC8032）算术（`_padd/_pmul/_compress/_decompress`），**不 import 附件代码**；
- 差分得相对偏移 → 256 基值英文似然定基 → 重建明文 → `_FLAG_RE` 搜 flag，
  有 `flag_sha256` 时逐字校验；命中写事实黑板缓存。
- 接入 `_tasks` 并发嗅探（第 31 路）。

**测试** `tests/test_ecxor_presolve.py`：合成正例 1（自造密文，端到端复现）+ 负例 3
（无曲线指纹 / 随机点无 flag / sha 不符）+ 真题 e2e 1。

---

## 4. 验证

- **回归**：presolve+KPI+leak 组合 **137 passed / 5 skipped**；提交门禁相关（antifraud/honesty/lease/export）**80 passed**。**零回归**。
- **全池假阳性扫描**：对 10 个题池去重 **234 题**逐一单跑 `_try_ecxor` →
  **命中 2 处，均为同一道 ECXOR 题**（`questions_ext` 与 `questions_ext_A_20261001` 各一份），**零假阳性**。
- **变异验证**：临时去掉「大写降权」（退化为大小写折叠）→ 合成正例**按预期转红**（`fLag{sYnth_…`），
  4 负例仍绿；复原后全绿。证明该约束是测试真守卫、非装饰。

---

## 5. 诚实口径与边界

- 本轮全部为 **presolve 命中**，**不是 LLM 自主解题**；不计入 LLM 自主解题率。
- 「crypto 候选可确定性攻破」是对 **`questions_ext` 池这一小样本**的陈述，**不可外推**为全局解题率。
- 未跑 LLM 主链（¥0 离线构造 + sha256 自检），无预算/环境缺陷干扰，结论可复现。
- collusion / des2bites / m_ster_0f_prn9 **本轮未深攻**，如实标注未破，不臆断原因。

---

## 6. 下一步候选（留给下一轮）

| 题目 | 可解性预判 | 依赖 |
|---|---|---|
| **collusion** | 纯数论可解：两把密文钥 `d_B,d_C` → `W = d_B·d_C·(n_B−n_C) − (d_C−d_B)` 是 `φ(N)` 的倍数 → 由「φ 的倍数」分解 N → 目标身份解密。需复刻 Go 确定性 PRNG（AES-256-CTR 零流 + `rand.Int`）算 `n_B/n_C`。 | 纯 Python（+AES） |
| **des2bites** | 附件 `DES2Bytes.enc` 为**纯十进制数字串**（27136 位、`0913334` 强周期前缀），非直接密文 → 需先破其编码；提示两把 DES 弱密钥（4×4=16 组合）。 | pycryptodome（venv 有） |
| m_ster_0f_prn9 | 本机**不可行**：截断 LCG 需格基约简（fpylll/SageMath 均无）→ 按铁律不投入。 | ✗ |
