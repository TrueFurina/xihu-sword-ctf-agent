# 无赛期系统精进实证（2026-09-01）— 预算加固 / presolve 矩阵 / LLM 真推理 / MV 换题

> 无赛期持续精进轮的实证结论。原始数据：`ctf_agent/data/results/`（本地，gitignore 不入库）；
> 本文件是结论的仓库级存档。口径：kpi9 诚实 8 题 + 新增 LLM 真推理 6 题、provider=mimo、诚实 KPI 只计 real_past_ctf。

## 1. 步级硬停边界兜底（B1 首跑 exit=1 事后防护）

- **问题**：B1（80K cap 步级）首跑 exit=1 无 traceback 无报告（瞬态，重跑正常）；审计发现
  `solve_once` 的 `agent.solve` try 只有 finally、无 except——任何子路径（监督/工具/目标指令）
  未捕获的 `BudgetExceeded` 会逃逸出 solve_once，且错误归因退化成 solver_exception。
- **修复**：solve_once 边界加 `except BudgetExceeded`，转成与 `budget.check` BUDGET_STOP 一致口径的
  `budget_exceeded` 输出（含 qid/used/cap 明细），预算异常永不击穿整场评测。
- **实战验证**：LLM 试跑中 2 题（babymaze/cm1）在 40K cap 下**优雅 budget_exceeded 中止**、exit=0、
  归因正确——边界兜底与步级硬停在真实链路工作正常。

## 2. presolve 覆盖矩阵（31 题干跑，零 LLM 成本）

结果存档 `data/results/presolve_matrix.json`。评估 31 题：**presolve 命中 13 / 未命中 18**（跳过 61）。

| 分类 | 命中 | 未命中 | 说明 |
|---|---|---|---|
| pwn (2) | 2 | 0 | flag 在二进制内被 flag_scan 命中 |
| reverse (9) | 4 | **5** | 未命中：easycm/notright/babymaze/cm1/timeflies |
| web (13) | 1 | **12** | 仅 soeasy 命中；SSTI/JWT/原型链/SQL盲注/命令注入类全 MISS |
| misc（高价值子集 7） | 6 | **1** | 未命中：BeCare4（零宽隐写） |

**结论**：presolve 引擎覆盖 crypto/misc 确定性题 + 二进制 flag 扫描；**web 12 + reverse 5 + misc 1 = 18 题是覆盖缺口**——presolve 覆盖率提升的靶区。

## 3. LLM 真推理试跑（presolve 覆盖缺口 6 题）— 贡献 = 0

试跑集 `data/questions_llm_trial/`（6 题：babymaze/cm1/timeflies + spookifier/linectf_ssti_jwt + BeCare4，
全部 presolve 未命中、flag 已知、disclosed=False）。presolve-skip + 40K cap + mimo：
**tokens 150,781 | 解出 0/6**。

| 题 | 归因 | 说明 |
|---|---|---|
| BeCare4 / timeflies / spookifier / linectf_ssti_jwt | hallucination | 跑满 3 重试，flag 被提取校验拒绝（含 EASY 的 Mako SSTI） |
| babymaze / cm1 | budget_exceeded | 40K cap 优雅中止（验证 §1 边界兜底） |

**结论（C2/C3 决策）**：
- 结合 kpi9（presolve-skip 下 LLM 0 独有解）+ 本试跑（0/6）→ **LLM 真推理贡献 = 0（当前真实语料）**。
- **C2/C3 维持暂缓**——不是题集问题，是 LLM 路径能力缺口（连 EASY SSTI 都未解出）。
- 改进方向：① 提升 LLM 步骤质量/flag 提取校验链路（4 题 hallucination 说明有产出但被拒）；
  ② 或者接受「presolve 优先」现实，把资源投向 §2 的 18 题 presolve 引擎开发（web 12 最优先）。

## 4. MV 驱动换题深化（赛智收尾）

- **发现**：`plan()` 构造 QuestionState 只填 qid/category——`marginal_value` 从未计算（全 0），
  DecisionEngine 的 MV 排序实际惰性。
- **实现**：① `plan()` 用 `_compute_marginal_value`（解出概率 × 分值 / 预计成本，按难度/分类/分值
  启发式）计算并填充 marginal_value；② `reflect_on_attempt` 沉溺保护加 **MV 守卫**——信心低+已重试时，
  MV ≥ 本轮峰值一半的高价值题 **CONTINUE**（多给机会），低价值题才 **SWITCH**；未规划题（benchmark
  路径）维持原行为。
- 验证：内联 3 场景（高价值 CONTINUE / 低价值 SWITCH / 未规划 SWITCH）全过。

## 数据存档

- `data/results/presolve_matrix.json`（覆盖矩阵）/ `data/results/llm_trial/benchmark_report.json`（LLM 试跑）
- 后台日志：`C:\Users\Lenovo\AppData\Local\Temp\presolve_matrix.log` / `aris_llm_trial.log`
- 试跑集：`data/questions_llm_trial/`（6 json，可复用）
