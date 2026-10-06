# 「nibble-swap → base64」解码链接通 —— 离线攻破 A5 held-out 的 Br3akTh3V@u1t

- 日期：2026-10-07
- 会话：atomcode-nibble
- 结论：**A5 五题可离线确定性攻破数由 3/5 → 4/5**；新增一条通用编码链能力（零成本、离线、过沙盒）
- 提交：`d9e4e49`（实现）+ `70f933b`（测试）→ `origin/main=70f933b`
- ⚠️ 诚实口径：本刀属 **presolve 确定性命中，不计入「LLM 自主解题率」**；「4/5」仅对 A5 小样本，**不可外推**。

---

## 1. 问题（「能力存在但不可达」又一实例）

A5 held-out 五题中，`br3akth3vau1t`（CSAW-Quals 2023，forensics）此前未能离线攻破。本轮定位：

- 附件 `vars/main.yml`（即题目 `main.yml`）内藏三个变量：
  - `sus` = 一个大十进制整数（352 bit）
  - `sus1337` = `15295865591442899`（小整数）
  - `sus14` = 13536 字符的超长十六进制串
- **编码链**：这些「十六进制串 / 大十进制数」的**原始字节**经 **nibble-swap**
  （每字节高/低 4 位互换）后，恰为 base64 文本；`b64decode` 即得明文。
- 现网 **没有任何 handler 覆盖「nibble-swap」这一步**：
  - `agents/crypto_toolkit.decode_multi_layer` 只做 hex / url / base64 往返；
  - `agents/misc_toolkit._TRIAGE_BODY` 只做 strings / ZIP / LSB / 摩斯 / Brainfuck / DNS。
  → 能力（base64 解码）早已存在，被一层「半字节交换」挡在门外，**恒不可达**。

## 2. 攻破实证（过沙盒复现，sha256 逐字匹配）

```
sus (十进制) → int→大端 bytes → nibble-swap → base64
  → csawctf{w@11_ST_1s_n0t_n3ce$$@ry}
sha256 == b3c9db6b888f9118ff301d8b0122faad5f43bd9a31a21c159ffd87046229c237  ✅（题目真值）
```

同附件的另两个变量为干扰项（同变换后）：

| 变量 | nibble-swap→base64 结果 | 含 flag？ |
|---|---|---|
| `sus` | `csawctf{w@11_ST_1s_n0t_n3ce$$@ry}` | ✅ 本题真值 |
| `sus1337` | `1337` | ✗ |
| `sus14` | 《A Cypherpunk's Manifesto》全文（5075 字节） | ✗ |

## 3. 改动与设计

`core/presolve.py` 新增 handler `_try_nibble_b64_decode`，注册进并发 dispatch：

- **扫描全部附件**（关键：`build_misc_fallback_script` 只传 `attach[0]`，而真值在
  `main.yml`(attach[2])，旧 misc 兜底链**结构上够不到**——故必须走 presolve 全附件扫描）。
- 候选 token：hex 串 `[0-9A-Fa-f]{16,}` / 大十进制数 `\d{20,}`。
- 变换：→ bytes → nibble-swap → **必须全落 base64 字符集** → `b64decode` → 搜 flag 模式。
- 与题库描述解耦；单附件读取上限 512KB（防超大二进制拖慢）。
- 命中由下游 `flag_pattern` + `_passes_answer_check`（题面提供真值时）双重把关。

## 4. 验证

- **端到端**：A5 五题走真实 presolve → 4 题命中（另一题 `free_as_in_freedom` 需 radare2，本机无）。
- **零假阳性**：186 个题目 JSON（本地库 + 全部外部池）全量扫描本 handler，
  仅 `br3akth3vau1t` 命中且 sha256 匹配，**零假阳性**。
- **变异验证**：把 `_nibble_swap` 改为恒等 → 3 个正例必红、3 个负例仍绿（按预期）。
- **回归**：新增 6/6；presolve+KPI+leak 组合 132/132；pre-commit 快速回归 152/152。**零回归**。

## 5. A5 现状（honest）

| 题 | 类型 | 状态 | 攻破方式 |
|---|---|---|---|
| lowe | crypto | ✅ 解出 | PEM→(N,e) + small_e 跨模 → file.enc ⊕ K |
| babycrypto | crypto | ✅ 解出 | base64→单字节 XOR 0xFF |
| another_xor | crypto | ✅ 解出 | flag+key+md5 结构还原（repeat-key XOR） |
| **br3akth3vau1t** | forensics | ✅ 解出 | **大十进制数 → nibble-swap → base64** |
| free_as_in_freedom | rev | ❌ 未破 | 需 radare2 语义（本机无 r2，静态还原未完成） |

> 均为 **presolve（确定性）命中**，非 LLM 自主解题；「4/5」不可外推。

## 6. 下一步

- `free_as_in_freedom`：`welcome2.r2` 为自修改 r2 脚本（4305 字节被 `wx` 写入内存后由 90 个
  `hit*` 位置 + 宏 `(a,psz > /tmp/x,. /tmp/x)` 驱动），需精确模拟 r2 的 `pc*`/`w1`/`wr` 语义，
  或静态还原；**本机无 r2，跨架构/容器验证不可行**（见记忆红线）。
- 继续排查其余「能力存在但不可达」的编码/布局入口。
- 平台仍 `40403 无权操作`，归一化等使能刀的真实收益需平台放闸后经 LLM 链验证。
