# held-out 实测 · 仓内证据（PROVENANCE）

本目录把 2026-09-19 held-out 池 LLM 实测的**两份原始 `benchmark_report.json`** 纳入版本库，
使 README / 汇报中引用的数字**在仓内可溯源、可自校验**。数据来源本身位于 gitignored 的
`ctf_agent/data/results/*`（见 `ctf_agent/.gitignore:113:/data/*`），此前不在 git 中。

## 文件与哈希（自校验）
两份副本均为**逐字节复制**，**副本哈希与源逐字相同**，任何人可用 `sha256sum` 自行核对。

| 本目录副本 | 源文件 | sha256（源 = 副本，逐字相同） |
|---|---|---|
| `benchmark_report_A_deepseek_1x.json` | `ctf_agent/data/results/heldout_rerun20260919_deepseek_full/benchmark_report.json` | `aa30d3c12e3f4ca5ec5462c00587f2e17c3da4afaf4f3a52cbc162a7efd26297` |
| `benchmark_report_B_deepseek_2x.json` | `ctf_agent/data/results/heldout_rerun20260919_ds_budget2x/benchmark_report.json` | `6ce3bfe0f6a99fde67691637f1bbfc8c04fecc23c2e27fb58cb38482ef3c5aea` |

自校验命令：`sha256sum ctf_agent/heldout_evidence/benchmark_report_*.json`

## 明文 flag 说明
报告内 `real_reverse_js` 的 `flag` 为**明文**。**未做任何脱敏**——这符合现行政策：
用户 2026-08-29 指令「flag 明文公开无实质风险，全都不管了，全都公开！除了我的 api、token」、
2026-09-01 再确认「永远，不管答案密钥泄露」。唯一硬红线为**凭据**（见
`ctf_agent/scripts/release_export.py` 的 `SECRET_PATTERNS`）；本目录不含任何凭据。

## 两份证据的内容摘要（供核对）
- **A（budget 1×）**：`mode=real_main_agent`，`total=10`，`solved=1`，`by_solved_by={main_agent_llm:0/5, unknown:0/4, presolve:1/1}`，`tokens.global_total=566570`；失败 = budget_exceeded×6 / hallucination×3。
- **B（budget 2×）**：`mode=real_main_agent`，`total=10`，`solved=1`，`by_solved_by={main_agent_llm:0/9, presolve:1/1}`，`tokens.global_total=696506`；失败 = hallucination×6 / tool_failure×2 / extract_fail×1。
- 结论：**池内 1/10（唯一解 = 确定性 presolve，非 LLM）/ LLM 自主推理 0/10**；预算翻倍后 `budget_exceeded` 清零而 LLM 仍 0 解 ⇒ **能力不足，非预算不足**。

## 运行与仓库元数据
- 两 run 均由**另一并发会话**执行（非本目录作者）；作者仅直读其报告原文并**原样**归档。
- 归档日期：2026-09-19。
