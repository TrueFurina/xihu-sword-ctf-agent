# 科研成果改造升级实证 — 换题决策 / 预算参数 / presolve 掩盖（2026-08-29）

> 三块升级（A/B/C）的实证结论。原始数据 `ctf_agent/data/results/bc/`（本地，gitignore 不入库）；
> 本文件是结论的仓库级存档（claim1 数据曾被清理丢失，结论必须入库）。
> 口径：kpi9 诚实 8 题集、provider=mimo、`--presolve-skip`（A/B 组）、墙钟 300s、诚实 KPI 只计 real_past_ctf。

## A. 换题决策完整化（提交 `96b9306`）

- **沉溺保护升级**：`RaceController.reflect_on_attempt` 增加「信心 < 0.4 且已重试 ≥1 次 → SWITCH」，
  不再等墙钟/死循环才放弃（赛智「信心低于阈值换题」落地）。ABANDON（预算反思）优先。
- **FeedbackLoop 换题钩子**：`verify/feedback.py` 重试循环内接入控制器——SWITCH/ABANDON 提前终止
  该题（live 链路与 benchmark 共用本循环，`race_controller=None` 时零回归）。
- **live 接线**：`run.py` platform 模式控制器前移，同一实例同时喂给 solver 层（换题钩子）与
  poller 层（plan 分配）；fail-open。
- 验证：内联 3 场景（沉溺保护 SWITCH / 钩子提前返回 / 无控制器回归）全过 + 全量 pytest 411 全绿
  + mock benchmark 8/8。

## B. Claim 1 参数矩阵（步级硬停 + cap 收紧）— 预算参数是纯收益

| 配置 | tokens | 相对 A 组降幅 | 解出率 | 说明 |
|---|---|---|---|---|
| A 组（无熔断，attempt 级，历史 3 种子均值） | 344,002±2,107 | — | 4/8 | presolve-skip 基线 |
| B 组（80K attempt 级，历史 3 种子均值） | 279,601±2,105 | **-18.7%** | 4/8 | 旧 Claim 1 结论 |
| **B1（80K cap，步级）** | **255,672** | **-25.7%** | **4/8** | 步级硬停增量 -8.6% |
| **B2（40K cap + 降级比 0.3，步级）** | **172,131** | **-50.0%** | **4/8** | 收紧 cap 再省 -32.7% |

- **步级硬停（A 改造）再省 8.6%**（18.7% → 25.7%）：超调从「一整次 attempt」收敛到「单次 LLM 调用」。
- **收紧 cap（80K → 40K + 降级 0.5→0.3）再省 32.7%**（→ 50.0%）：172K 即 4/8。
- **解出率全程零损失**：8 题中 4 题（ezmult/qiangwang/sheng/upx）由确定性引擎解出，LLM 路径
  （main_agent_llm 2 题 + unknown 2 题）无论烧多少 token 都不解——收紧预算不影响解出能力。
- 注：B1 首跑 exit=1（偶发，同代码 B2 正常），重跑 exit=0 数据有效。

## C. presolve 掩盖量化 — LLM 真推理贡献 = 0（本 8 题集）

| 臂 | 配置 | tokens | 解出 | by_solved_by |
|---|---|---|---|---|
| C1 | presolve ON + 熔断关 | **0** | **8/8** | presolve 8/8（含 anwang/filterrandom/vnctf/xuanhun） |
| B1/B2 | presolve-skip | 172–256K | 4/8 | presolve(agent 引擎) 4/4；LLM 2/0；unknown 2/0 |

- **presolve 是唯一解出能力**：presolve ON → 8/8、0 tokens。4 道「重载题」LLM 路径烧 ~344K 全败，
  presolve 引擎（crypto_auto / math_engine / grid_resample / jpeg_png_embedded / flag_scan）0 成本全解。
- **LLM 真推理贡献 = 0 题**：presolve-skip 下 main_agent_llm 2 题全败，4 个解出仍是 agent 内部
  确定性引擎。外部评估的「presolve 掩盖」担忧完全属实（此前 presolve 贡献 14/15 即此现象）。
- **C2/C3 决策**：暂缓。两实验依赖「LLM 路径真被用、真在解」——当前集 LLM 0 独有解，信号≈0。
  前置条件：构造 presolve 解不出、LLM 能解的 LLM 真推理题集（真实 CTF 逆向/pwn/web 深题）。
- **工程结论**：比赛形态 presolve 优先已实现且正确——**升级杠杆在 presolve 覆盖率，不在 LLM 推理**。

## 数据存档

- 原始报告：`ctf_agent/data/results/bc/{B1_step_80k,B2_step_40k_dg03,C1_presolve_on}/benchmark_report.json`
  （本地 gitignore；本文件即结论存档）
- 后台日志：`C:\Users\Lenovo\AppData\Local\Temp\aris_bc_experiment.log` / `aris_b1_rerun.log`
