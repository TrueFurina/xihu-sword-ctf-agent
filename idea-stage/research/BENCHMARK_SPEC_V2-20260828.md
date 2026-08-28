# Benchmark 规格 V2（修正版）— 2026-08-28

> 背景：外部评估（`方案评估-IDEA1可行性效度评审-20260828.md`）指出缺陷 A：原方案自称"40 道西湖论剑真题"实为 `data/questions/` 下 **41 个自产教学题**（`self_authored_training`），honesty 框架明令不计分——解出=阅读理解而非推理，主指标失效。本规格重定评测口径（P0-1 落地）。

## 1. 题集口径

### 1.1 合法题集：诚实 KPI 9 题（台账 `REAL_SOLVES_LEDGER.md` 第二节，offline_verified=9）

| # | 题 ID | 类型 | 本地可批量跑 | 附件 |
|---|---|---|---|---|
| 1 | 10733（CRYPTO-02 How_many_rot_are_there） | A 完整攻击链 | ⚠️ 仅 verify 脚本 | 归档区 |
| 2 | real_misc_vnctf_flag | A 完整攻击链 | ✅ | ✅ |
| 3 | real_misc_xuanhun_signin | A 完整攻击链 | ✅ | ✅ |
| 4 | real_reverse_sheng | A 完整攻击链 | ✅ | ✅ |
| 5 | real_reverse_upx | A 完整攻击链 | ✅ | ✅ |
| 6 | real_crypto_anwang_crypto1 | B presolve 变换 | ✅ | ✅ |
| 7 | real_crypto_ezmult | B presolve 变换 | ✅ | ✅ |
| 8 | real_crypto_filterrandom | B presolve 变换 | ✅ | ✅ |
| 9 | real_crypto_qiangwang_classic | B presolve 变换 | ✅ | ✅ |

- **10733 特殊处理**：题面 json 在 `_archive/ctf_agent_broken/data/race_details/10733.json`（活跃库缺失，`data/race_details/` 仅剩 10732.json）；当前 `scripts/verify_10733.py`（内嵌 hint/c/n/e 参数）可独立核验。批量评测前需从归档恢复题面+附件，或单题走 verify 脚本。
- **已移出严格 KPI**（unreproducible）：specialcurve2 / 10732 / 10735 / ezrsa / simplelegendre / exciting_inverse（台账 2026-08-27/28 诚实校准）。

### 1.2 禁用集：41 自产教学题（`data/questions/`）

- 判定：`grep -rl "self_authored_training" data/questions/` = **41 文件**（实测）
- 原因：flag 自定、答案常写题面 → 解出=阅读理解非推理
- **任何实验不得以 `data/questions/` 为基准**（--questions-dir 必须指向 questions_real）

## 2. 运行命令模板

```bash
# 基准跑（真实 LLM，8 题可批量 + 10733 单独核验）
python eval/benchmark.py \
  --questions-dir data/questions_real \
  --provider <provider> \
  --wallclock 300 \
  --limit 9

# 隔离 presolve（强制主 Agent 全链路，测 LLM 路径专用）
python eval/benchmark.py \
  --questions-dir data/questions_real \
  --provider <provider> \
  --presolve-skip \
  --wallclock 300 \
  --limit 9
```

- provider：`CTF_AGENT_LLM_PROVIDER` 或 `--provider` 显式指定（xfyun/ark/dashscope 等已有 key；MiMo 接入需确认 `llm/client.py` provider 列表）

## 3. 统计口径（≥3 种子 + CI）

- 每配置 **≥3 次独立重复**（不同 seed/温度采样），先确认 benchmark.py 是否透传 seed；无则用温度/时间戳区分
- 报告：解出率（x/y 题）、Token 总消耗**均值 ± CI**、每题 token 分布
- 显著性：解出率用 McNemar（配对）；Token 用配对 t / Wilcoxon
- **成功判据不以凭空目标值为准**：先跑全关基线，再谈 delta（评估缺陷 C）

## 4. Claim 1 实验矩阵（熔断降 Token）

| 配置 | presolve | 熔断（budget.py） | 目的 |
|---|---|---|---|
| A 全关（基线） | skip | off | 先拿基线数字 |
| B 熔断开 | skip | on | 测熔断降 Token |
| C 真实链路 | on | on | 含 presolve 的完整链路 |

- 熔断层：`scheduler/budget.py` `BudgetTracker`（单题 token 上限 / 全局预算 / 重试上限 / `BUDGET_OK|DOWNGRADE|STOP` 三态）——**已存在**，Claim 1 是配置开关而非从零写
- Token 记账：`llm/client.py ai_chat_json_with_usage`（真实 token usage）

## 5. 污染自检（评估缺陷 C / T5）

- **RAG-off**：禁读 writeup/历史解答的配置重测，隔离记忆污染（G1）
- **presolve 隔离**：`--presolve-skip` 区分"确定性管线"与"LLM 路径"贡献（回应"14/15 presolve 直出、LLM 贡献≈0"）
- **台账诚实口径**：解出必须 flag_sha256 双源验证（现有机制复用）

## 6. 配套已知缺口（执行前需闭环）

1. 10733 题面 json 从 `_archive/ctf_agent_broken/` 迁回活跃库（或实验集先标 8 题）
2. MiMo provider 接入确认（或选用已验证 provider：xfyun/ark/dashscope）
3. benchmark.py seed 透传确认（无则用温度区分重复）
4. 熔断开关方式确认（AppConfig 字段？环境变量？）——决定"全关 vs 熔断"怎么切
