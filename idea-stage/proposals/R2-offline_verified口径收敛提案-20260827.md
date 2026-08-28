# offline_verified 口径收敛提案（R2）

> 提出：2026-08-27 00:2x（质检后续推进）
> 性质：诚实性红线决策，需协调者/用户拍板后执行
> 关联：`质检报告-风险与问题-20260826.md` 的 R2/R6/R7

---

## 一、问题：offline_verified 三套数字并存

| 来源 | 数字 | 口径 |
|---|---|---|
| 台账 `REAL_SOLVES_LEDGER.md` 第二节（merge_gate 唯一认） | **5** | 独立攻击链离线核验 |
| `KPI_BASELINE.json` 棘轮锚 | **5** | 同上 |
| 项目长期备忘 | **8** | 「曾虚高7→真实5→ezrsa→7→simplelegendre→8」 |
| 8-26 commit 消息 / 攻坚文档 | **第10项** | 累加确定性解出 |

## 二、根因

攻坚会话（atomcode-overseer）在 gitignored 的《主Agent失败步攻坚实验设计-20260825.md》里，把 presolve 确定性管线解出的 crypto 真题写成「offline_verified 第 N 项」（累加计数）：

- 第 7 项 = +ezrsa
- 第 8 项 = +simplelegendre
- 第 9 项 = +ezmult
- 第 10 项 = +dnui_keyboard

但这 5 题**从未同步进台账第二节**。台账第二节只有 specialcurve2/10732/10733/vnctf_flag/10735（5 项）。`merge_gate.count_offline_verified()` 只数台账 → 恒为 5。所谓「第10项」是 gitignored 文档里的纸面数字，无闸门背书。

## 三、关键事实核查：这 5 题是真攻击链，不是「抽答案」

台账第四节曾称「presolve 是确定性模板，直接从题面真值文件抽答案，没有攻击链」。**对 crypto 题这条说法是错的**——那是对 `flag_scan` 源码披露类（reverse_js / gongye_web2，2ms/7ms 直接 grep 明文）的描述。这 5 道 crypto 题的解法是 skill 真实实现的密码学变换：

| 题 | 真实解法 | verified_flags.json 落盘 |
|---|---|---|
| anwang_crypto1 | 八进制 ASCII + Vigenère | ✅ 明文+sha256 |
| ezrsa | Hastad 广播攻击 e=17 爆破 | ✅ |
| simplelegendre | 勒让德符号逐位解密 | ✅ |
| ezmult | base64 + ROT13 | ✅ |
| dnui_keyboard | QWERTY 键盘坐标连线 | ✅ 但「题面直接给 CLCKOUTHK」 |

## 四、收敛方案（二选一）

### 方案 A（推荐）：口径分离 + 正式收录 4 题
- 把 anwang_crypto1 / ezrsa / simplelegendre / ezmult **迁入台账第二节**（真攻击链 + flag 已落盘 + 双源验证）。
- **dnui_keyboard 不计入**（题面直接给答案，违反台账「答案已给出不计入」红线）。
- 结果：`offline_verified` 5 → **9**，重跑 `full_baseline` 抬棘轮锚到 9。
- 攻坚文档的「第 7-10 项」改注为「第 7-9 项已迁台账，第10项 dnui_keyboard 撤销」。

### 方案 B：维持 5，攻坚文档改口径
- `offline_verified` 严格 = 独立攻击链（维持 5）。
- 确定性管线（presolve 直出）= 另一口径（14/15，台账第二节-B 已记）。
- 攻坚文档「第 N 项 offline_verified」全部改为「确定性管线第 N 题」，与 offline_verified 脱钩。

## 五、我的推荐与理由

**推荐方案 A**：这 4 题是真攻击链、flag 已落盘、双源验证齐全，符合台账 offline_verified 定义，迁入后「唯一 KPI」才能真实反映能力；dnui_keyboard 单独剔除，避免题面泄露虚高。唯一代价是要重跑 `full_baseline` 让棘轮锚从 5 抬到 9（需确认这 4 题 flag 在 verified_flags.json 已落盘——已确认 ✅）。

方案 B 更保守，但会把「已经真实解出的 4 题」压在「确定性管线」口径下，低估能力，且无法根治「第 N 项」与台账的永久分裂。

---

**待拍板**：A 还是 B？确认后我立即执行（迁台账 / 改攻坚文档 / 重跑 full_baseline）。
