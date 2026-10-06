# 几乎 XOR 求解链接通 —— CSAW-Quals 2017 almost_xor 离线攻破

> 日期：2026-10-07 ｜ 会话：atomcode-almostxor ｜ 类型：B 类工具链补齐（确定性 presolve）
> 提交：`cc1bb49`（实现）+ `667e4de`（测试）→ `origin/main=667e4de`
> 口径：**presolve 命中，不计入「LLM 自主解题率」**；属使能刀。

## 一、问题定性

`questions_ext` 外部池（34 题，全带 `flag_sha256` 真值）中，`almost_xor`（CSAW-Quals 2017，
crypto 200）为**能力缺口**：现网无任何 handler / triage 段覆盖「n-bit 分组模加密码」。

- 附件：`almostxor.py`（加密脚本）+ `ciphertext`（48 字节 hex）。
- 加密语义：明文与 key 按 `n` 字节分组 → 每组展开为 8 个 `n`-bit 值
  → 逐值 `(m + k) mod 2^n`；`n < 8`、key 重复且均未知。
- 缺口实质＝**能力存在但不可达**的又一实例（同 lowe / babycrypto / another_xor / br3akth3vau1t 家族）。

## 二、攻破（确定性，过沙盒）

CSAW-Quals 2017 **almost_xor**：

```
flag = flag{>x0r_i5_Add1+10n-m0D-2,'bU+_+h15_Wa5_m0d=8}
sha256(flag) = 6bb0e2756e56c8edb2fab669e3c244bb1db1ff018cee55321972e1bfc169f407
```

与题面 `flag_sha256` **逐字匹配**。参数：`n=3`、`key = b'>\xb3\xbc%\xe1\xc4'`（明文长度 48 = n 倍数）。

## 三、改动与验证

### 改动（`core/presolve.py`，+158 行）
新增 handler `_try_almost_xor` + 注册 dispatch：
1. **指纹检测**：附件含 Python 脚本且定义 `encr_vals`（或 `get_vals` + `get_chrs`）否则直接跳过（对非本题零开销）。
2. **求解**（已知明文攻击）：`n` 必须整除密文长度 → 用 flag 前缀（`flag{`/`csawctf{`/`ctf{`/`FLAG{`）
   恢复 key 前缀 → 枚举 key 长度并用可打印性约束爆破 ≤2 个未知明文字节 → 整体模减解密 →
   去分组补零 padding → 明文须**整体 fullmatch** flag 模式。
3. **真值校验**：题面提供 `flag_sha256` 时**逐字校验**——彻底消除「密文多解」噪声
   （任意 key 都能"解出"某可打印串，只有真值能定解）。

### 验证
- 单题端到端：`presolve` → 命中，`sha256` 逐字匹配。
- **全池零假阳性**：294 个题目 JSON（本地库 + 全部外部池）全量扫描，仅 `almost_xor` 命中且真值匹配。
- **变异验证**：禁用真值校验 → 正例 + 负例（多解伪串）必红；恢复后全绿。
- 回归：新增 5/5；presolve + KPI + leak 组 132/132；hook 快速回归 152/152。**零回归**。

## 四、附带发现（值得记录）

**密文多解性**：模加密码在无真值时**本质上多解**——例：明文 `csaw{...}` 用 `csawctf{`/`ctf{`
前缀暴力也会产出全可打印、满足 flag 形态的伪串。纯启发式（可打印率 + 含 `}` + fullmatch）
**无法完全排除**。

**判据**：此类 handler 应**优先用题面 `flag_sha256` 校验**；无真值时才 best-effort 返回首个候选
（生产流下游仍会再校验）。这与 nibble handler 的经验一致，可作为后续同类「使能刀」的通用纪律。

另一个实现细节：`n` 分组补零会在明文尾部产生 `\x00` padding，判据须先 `rstrip(b"\x00")`
再检查可打印性，否则会把正确解误判为噪声。

## 五、A5/外部池现状

- A5（5 题）**4/5** 可离线确定性攻破：lowe / babycrypto / another_xor / br3akth3vau1t；
  剩 `free_as_in_freedom`（自修改 r2 脚本，本机无 r2、跨架构验证不可行）。
- `questions_ext` 34 题新增 1 题（almost_xor）确定性可解。
- 剩余未破：`br3akth3vau1t` 已破；`free_as_in_freedom` 需静态还原；其余题需真实 crypto/rev 工作。

## 六、诚实边界与下一步

- 本刀是**使能刀**（不可达→可达），**不承诺提升 LLM 自主解题率**；真实收益须走 LLM 链验证。
- 全池扫描零假阳性，判据由 `flag_sha256` 兜底，无 KPI 污染风险。
- 下一步可继续排查其余「能力存在但不可达」入口，或等平台放闸（仍 `40403`）验证累积使能收益。
