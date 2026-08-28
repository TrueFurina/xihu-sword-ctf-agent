# 反注水法令（写死 · fail-closed）

> 立法依据：用户 2026-08-27 严令——**「本项目必须超级严格禁止一切注水行为！
> 所有注水行为都将收到严厉惩罚！写死！」**

本文件是本项目诚实口径的**机器执法条文**。它不是一个建议，而是一条写进代码、
无法靠自觉性绕过的铁律。任何会话（含人类）、任何分支、任何提交，只要触碰注水，
一律被机器拦截并永久留痕。

---

## 一、什么是「注水」（定义）

下列任一行为即构成注水：

1. **虚增 / 虚报 KPI**：`offline_verified` 解出数偏离写死真值锚 `KPI_WATERMARK`（当前 = 基线 `BASE_WATERMARK = 9` + 证据化晋升数）；跌破地板或溢出无证据晋升均属注水；
2. **泄露式假验证**：在仓库 / 脚本 / commit 中硬编码真实 flag 字面量，或预植
   `EXPECTED = "flag{...}"` 答案后以「自比通过」冒充「真解出 / 真推理」；
3. **口径走私**：把不可复现项（如 specialcurve2 / 10732 / 10735）、外部真题、
   self-authored 训练项计入严格 KPI；
4. **篡改基线**：改动 `KPI_BASELINE.json` 的 `offline_verified` 以重置棘轮 / 粉饰水位；
5. **话术包装**：在 commit message 中以「LLM 推理贡献 / 破冰 / 从 0 突破」等声称
   包装上述任何一种注水。

---

## 二、写死的真值锚（不可经任何文件篡改）——「证据化地板」模型

- `BASE_WATERMARK = 9` —— **硬编码常量**，不可下破的地板（回归即阻断）。诚实校准
  （2026-08-28）：原 12 中 ezrsa / simplelegendre / exciting_inverse 三道现行确定性管线
  presolve 提取=None（不可复现），已移出严格 KPI 并列入 `_merge_gate.KNOWN_GAP`。
- `KPI_WATERMARK = BASE_WATERMARK + len(PROMOTION_EVIDENCE)` —— **派生常量**，不读取任何
  可被编辑的文件。水位 = 基线 9 + 证据化晋升数；对账结果 `!= KPI_WATERMARK` 即判定注水。
- `AUTHORIZED_KPI_SOLVES = BASE_AUTHORIZED_KPI_SOLVES ∪ PROMOTION_EVIDENCE.keys()` ——
  当前 9 个授权题块的 ID 级白名单（`10733`、`real_misc_vnctf_flag`、
  `real_crypto_anwang_crypto1`、`real_crypto_ezmult`、`real_misc_xuanhun_signin`、
  `real_crypto_filterrandom`、`real_crypto_qiangwang_classic`、`real_reverse_sheng`、
  `real_reverse_upx`）。凡被计入严格 KPI 的题块必须在此集合内；缺失即视为被擅自降级。
- `PROMOTION_EVIDENCE` —— 证据化晋升字典（>9 的部分），每道必须带可审计证据字符串
  （`sha256:<真值摘要>|verify:scripts/_regress_one.py <id>|pr:<PR链接>`）。白名单含超额
  题块却无本条记录 → `PROMOTION_WITHOUT_EVIDENCE` 阻断（无证据注水）。
- 不可复现项（`real_crypto_specialcurve2` / `10732` / `10735`）永久标 ⛔，
  不计入严格 KPI，机器强制排除。

> **带证据可晋级（修复「等式锁」治理过拟合）**：真实进展到 10/13 题不再被当注水误杀。
> 合法晋升路径 = 提 **promotion PR**：① 在 `_merge_gate.REGRESSION_CHECKS` 新增**真跑通过**
> 的可复现验证；② 在 `PROMOTION_EVIDENCE` 追加证据字符串；③ 同增 `AUTHORIZED_KPI_SOLVES`；
> ④ 同步抬升 `KPI_BASELINE.json` 的 `offline_verified`。机器 fail-closed 拒绝任何
> 「只抬台账计数 / 只改常量却无证据 / 悄悄加项」的单边篡改。

---

## 三、严厉惩罚（永久留痕）

每一次注水企图，无论最终是否成功提交，都会被机器写入
`governance/anti_fraud/violations.jsonl`——一条 **tamper-evident、可审计、
可追责**的永久记录，包含：

- `ts`： attempt 时间戳（东八区）
- `session`： 发起会话标识（CT_AGENT_SESSION 或 git author）
- `rule`： 触犯的法条（WATERMARK_DRIFT / WATERMARK_REGRESSION / PROMOTION_WITHOUT_EVIDENCE /
  UNAUTHORIZED_SOLVE / BASELINE_TAMPER / LEAKED_DEMO / STAGED_LEAK / LEAKED_FAKE_LLM /
  LEAKED_FLAG_IN_MSG …）
- `severity`： BLOCK
- `outcome`： BLOCKED
- `detail` / `path` / `snippet`： 违规详情（敏感片段脱敏）
- `kpi_watermark`： 当时的写死水位

该文件纳入版本控制，**不可被 `.gitignore` 忽略**。注水者无法靠删除记录掩盖行为——
记录一旦写入即进入本仓库可追溯历史。

---

## 四、机器执法点（fail-closed）

| 入口 | 触发时机 | 执法内容 |
|---|---|---|
| `pre-commit` ⑩ | 每次 commit | 水位 + 泄露 + 暂存区泄露 + 授权走私 + 基线篡改 |
| `pre-merge-commit` | 每次 merge | 全量执法（`_merge_gate` 之后） |
| `commit-msg` | commit message 写入 | LLM 突破声称须无预植答案 / 硬编码 flag |
| `pytest tests/test_antifraud.py` | CI / 本地 | 各法条阻断行为单测覆盖 |

任一入口检出注水 → `exit 1` 阻断提交 / 合并，并落账。

---

## 五、红线重申

- **不注水**是本项目最高优先级约束，高于任何「进度 / 演示 / 跑分」诉求。
- 真实能力增长只能来自**可复现的验证**与** genuine 的推理**，不得以任何形式虚构。
- 发现注水企图 → 记账、阻断、上报，**绝不悄悄放过**。
