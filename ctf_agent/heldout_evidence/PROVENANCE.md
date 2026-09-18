# held-out 实测 · 仓内证据（PROVENANCE）

本目录把 2026-09-19 held-out 池 LLM 实测的**两份原始 `benchmark_report.json`** 纳入版本库，
使 README / 汇报中引用的数字**在仓内可溯源、可自校验**。数据来源本身位于 gitignored 的
`ctf_agent/data/results/*`（见 `ctf_agent/.gitignore:113:/data/*`），此前不在 git 中。

## 文件与哈希（自校验）
| 本目录副本 | 源文件（绝对/相对路径） | sha256(源) | sha256(副本) |
|---|---|---|---|
| `benchmark_report_A_deepseek_1x.json` | `ctf_agent/data/results/heldout_rerun20260919_deepseek_full/benchmark_report.json` | `aa30d3c12e3f4ca5ec5462c00587f2e17c3da4afaf4f3a52cbc162a7efd26297` | `6a3c0be44d94d9d222d2c6d88ddeeaa28a1eae6106d7c03086c9f931a7aefd22` |
| `benchmark_report_B_deepseek_2x.json` | `ctf_agent/data/results/heldout_rerun20260919_ds_budget2x/benchmark_report.json` | `6ce3bfe0f6a99fde67691637f1bbfc8c04fecc23c2e27fb58cb38482ef3c5aea` | `441a6ce374fe7272aa4cf220f9b326b664eb7f5a33cf27dbc791dc6090f321d8` |

## ⚠️ 与"逐字节复制"的唯一偏离（安全红线）
源文件中 `real_reverse_js` 一条含**明文真 flag**（`results[6].flag`）。仓库红线明确
"散落明文 flag 绝不入库"（见 `ctf_agent/.gitignore` 第 14 节注释），且本仓正处于转公开流程。
故副本**仅**把该一处 `flag` 值替换为其 **sha256**，其余字节与源完全一致（定向替换，未重排/重格式化）。
- 被替换项：`real_reverse_js` 的 `flag` → `aec640f00c418c309bd68dcbfd389df969fa3393a68aee14690393908d2f6ef9`（sha256(明文)）
- 替换不影响任何可引用数字：`summary` 与两条件下的逐题 `solved/error/tokens/retries` **逐字段一致**（已断言校验 `summary_equal_except_flag=True`）。
- 若需严格逐字节原样入库，请指示——但会将该明文 flag 引入 git 历史（不可逆，且污染 held-out 干净度）。

## 两份证据的内容摘要（供核对）
- **A（budget 1×）**：`mode=real_main_agent`，`total=10`，`solved=1`，`by_solved_by={main_agent_llm:0/5, unknown:0/4, presolve:1/1}`，`tokens.global_total=566570`；失败 = budget_exceeded×6 / hallucination×3。
- **B（budget 2×）**：`mode=real_main_agent`，`total=10`，`solved=1`，`by_solved_by={main_agent_llm:0/9, presolve:1/1}`，`tokens.global_total=696506`；失败 = hallucination×6 / tool_failure×2 / extract_fail×1。
- 结论：**池内 1/10（唯一解 = 确定性 presolve，非 LLM）/ LLM 自主推理 0/10**；预算翻倍后 `budget_exceeded` 清零而 LLM 仍 0 解 ⇒ **能力不足，非预算不足**。

## 运行与仓库元数据
- 两 run 均由**另一并发会话**执行（非本目录作者）；作者仅直读其报告原文并原样归档。
- 归档时仓库 `HEAD = 41ffb076ffc6e979a56ae8d2000e5c214b71d8d9`。
- 归档日期：2026-09-19。
