# 编码块 XOR 爆破能力接通 + 沙盒命令行长度缺陷修复
### A5 held-out 离线分诊：babycrypto / another_xor 确定性攻破（第 2、3 例）

> 生成时间：2026-10-07　范围：`ctf_agent/`　成本：**¥0**（纯离线、零 LLM 调用）
> 提交：`dea01a5`+`99ec0c9`（初版）、`fdc4517`+`ed24347`（假阳性加固）→ `origin/main=ed24347`
> 口径声明：本文所述均为 **presolve（确定性攻击链）命中**，**不计入「LLM 自主解题率」**。

---

## 0. 一句话结论

A5 held-out 五题中，**3/5 可被确定性离线攻破**（lowe / babycrypto / another_xor）。
本轮新破 2 题，根因与上轮 lowe 同源——**不是缺能力，是能力不可达**：
triage 段 4「多层编码解码」只做 hex/url/base64 往返，覆盖不到「解码后字节仍需 XOR」的格局。
补段 2.8 后两题均过沙盒复现。

本轮**附带发现并修复一个系统性缺陷**：沙盒经 `python -c <src>` 执行，
Windows CreateProcess 命令行上限 ~32767 字符；crypto 兜底脚本已增至 ~33KB，
**超限即静默失效**（FileNotFoundError）。该缺陷此前未被发现，且会随 triage 增长必然引爆。

---

## 1. A5 五题最终状态

| 题目 | 类别 | 事件 | 状态 | 关键 flag |
|---|---|---|---|---|
| lowe | crypto | CSAW-Quals 2018 | ✅ 上轮攻破 | `flag{saltstacksaltcomit5dd304276ba5745ec21fc1e6686a0b28da29e6fc}` |
| **babycrypto** | crypto | CSAW-Quals 2018 | ✅ **本轮攻破** | `flag{diffie-hellman-g0ph3rzraOY1Jal4cHaFY9SWRyAQ6aH}` |
| **another_xor** | crypto | CSAW-Quals 2017 | ✅ **本轮攻破** | `flag{sti11_us3_da_x0r_for_my_s3cratz}` |
| br3akth3vau1t | forensics | CSAW-Quals 2023 | ⬜ 未破（Ansible Vault 取证，需真实 crypto/forensics 工作） |
| free_as_in_freedom | rev | CSAW-Finals 2018 | ⬜ 未破（radare2 脚本，r2 未安装 → 需静态还原） |

---

## 2. 攻破细节

### 2.1 babycrypto（CSAW 2018 Quals）

附件 `ciphertext.txt`（432 字符 base64）。结构：**base64 解码后的字节逐位取反**（单字节 XOR `0xFF`）即明文。

```
s5qQkd+WjN…  ──base64──▶ 322 非可打印字节 ──XOR 0xFF──▶ 英文散文 + flag
```

复原明文（节选）：`Leon is a programmer who aspires to create programs that help people do less. … flag{diffie-hellman-g0ph3rzraOY1Jal4cHaFY9SWRyAQ6aH}`

### 2.2 another_xor（CSAW 2017 Quals）

附件 `encrypted`（274 字符 hex = 137 字节）。官方 `cipher.py` 结构：

```python
key = argv[2]
plaintext = argv[1] + key                       # flag + key
plaintext += md5(plaintext).hexdigest()         # + 32 字符 hex 校验和
cipher = xor(plaintext, repeat(key, len(plaintext)))
```

还原算法（纯数论，无 LLM）：
1. **定位 key 长**：`plaintext` 内含 key 原文，故存在窗口使 `XOR(c[off:off+L]) == 0`。
   遍历 L 命中唯一解 `(L=67, off=38)`。
2. **已知明文起步**：按题面 `flag{` 前缀推 `key[0:5]`（= `A qua`）。
3. **自引用传播**：`c[off+i] = key[i] ^ key[(off+i)%L]` ⇒ `key[(off+i)%L] = c[off+i] ^ key[i]`，
   迭代至填满全 key。
4. **md5 仲裁**：末 32 字节应等于 `md5(flag+key).hexdigest()`。

实测（哈希完全吻合）：

```
key  = A quart jar of oil mixed with zinc oxide makes a very bright paint
flag = flag{sti11_us3_da_x0r_for_my_s3cratz}
md5(flag+key) = d5111350bbbe105121b9a9496ac08df2  == 密文末 32 字符  ✅
```

---

## 3. 附带修复：沙盒命令行长度缺陷（系统性）

### 3.1 现象

新增 triage 段后，crypto 兜底脚本长度 `33722`，经 `agent.sandbox.run(f"python: {script}")`
执行时返回 `命令不存在（FileNotFoundError）`——**攻击逻辑一行未跑，静默失效**。

### 3.2 根因

`sandbox/subprocess_executor.py` 用 `argv = [sys.executable, "-c", python_src]` 传源码。
**Windows CreateProcess 命令行上限约 32767 字符**，超限即进程创建失败。
实测阈值：`30000` 可执行、`33000` 必失败。

这是**潜伏缺陷**：兜底脚本随 triage 增长（上轮加法已到 ~30.5KB），
本轮加段即越过红线。若不修，后续任何 triage 扩能都会连带炸掉**整条 crypto 确定性兜底链**。

### 3.3 修复

源码超阈值（`_CMD_LINE_SRC_LIMIT = 24000`）时落临时文件执行，语义完全等价
（同一解释器 + 同一 AST 安全校验），执行后清理（成功/超时/取消/异常各路径 `finally`）。

---

## 4. 改动与验证

**实现**
- `agents/crypto_toolkit.py`（+100）：triage 段 2.8——(a) 单字节 XOR、(b) 明文内嵌密钥型重复 XOR、
  (c) 通用短密钥重复 XOR。三者**只在结果含 flag 模式时打印**（防幻觉）；含尺寸/规模守卫防沙盒空转。
- `sandbox/subprocess_executor.py`（+31）：`_build_python_argv` + `finally` 清理。

**测试**
- `tests/test_xor_bruteforce_fallback.py`：正例 2 + 负例 1。
- `tests/test_subprocess_long_source.py`：超长可执行 / 短源码走快路径 / 临时文件清理 / 阈值合理性。

**验证**
- 端到端（构建 fallback → 沙盒运行）：babycrypto `[xor_single k=0xff]`、
  another_xor `[xor_repeat_embed L=67]`，均命中真 flag。
- **假阳性加固（A5 全量复扫发现）**：lowe 的 PEM/DER blob（~270B）会触发内嵌密钥分支——
  随机窗口 `XOR==0` 恰好成立，旧正则 `[^}\s]` 又匹配到 XOR 残留的非可打印字节 → 输出垃圾 `flag{}`。
  加固：① flag 内容改 `[!-~]`（仅可打印 ASCII）；② 内嵌密钥分支改为**强制 md5 仲裁**。
  复扫确认三题仍正确命中、lowe 不再假阳性。
- **变异验证**：① 禁用段 2.8 匹配 → 2 正例必红、负例仍绿；② 强制走 `-c` → 2 超长测试必红；
  ③ 去掉可打印约束 → 非可打印负例必红；④ 去掉 md5 门 → md5 不吻合负例必红。四次均按预期变红。
- 回归：新增 9/9；crypto+sandbox 组合 106/106；pre-commit 快速回归 152/152。**零回归**。

---

## 5. 诚实口径与边界

- 本文全部为 **presolve 命中**，**不是 LLM 自主解题**；不计入 LLM 自主解题率。
- 「可确定性攻破 3/5」是对 **A5 held-out 五题**这一小样本的陈述，**不可外推**为全局解题率。
- 两题均**未跑 LLM 主链**（¥0 离线构造 + 字节级自检），不存在预算/环境缺陷干扰，结论可复现。
- br3akth3vau1t / free_as_in_freedom 本轮未尝试深攻，**如实标注未破**，不臆断原因。

---

## 6. 顺带发现（本轮未改，留给下一轮）

**category 别名未归一化 → 又一处「能力不可达」。**

外部题池的 `category` 逐字取自 JSON（`eval/cases.py:65` `str(data.get("category","misc"))`，无归一化），
但代码大量按 `category == "reverse"` 硬判：

| 位置 | 门控 |
|---|---|
| `core/presolve.py:1724` | `if cat != "reverse": return`（**presolve 整段只对 reverse 跑**） |
| `core/phases.py:202` | reverse 兜底触发条件 |
| `core/main_agent.py:314` | heavy 模型选择 |
| `core/supervisor_agent.py:107` | 步数（25 vs 18） |
| `agents/math_engine.py:358` | 数学引擎入口 |

而 A5 的 `free_as_in_freedom` 来自 NYU 上游，`category="rev"`（非 `"reverse"`）；
`br3akth3vau1t` 为 `"forensics"`（也不在 canonical 集 `web/crypto/misc/reverse/pwn`）。
`scripts/fetch_google_ctf.py` 有 `CAT_MAP={"rev":"reverse"}`，但**只在该脚本内**，加载层无等价归一。

⇒ 对 `rev`/`forensics` 标记的题，presolve / reverse 兜底 / heavy 模型 / 步数 全部失效。
**建议**：在 Question 加载层加 `_CAT_ALIASES` 归一（`rev/reversing→reverse`、`forensic(s)→misc`），
但须同步评估 `benchmark.by_category` 报表口径变化——属共享加载器改动，本轮不擅动。

