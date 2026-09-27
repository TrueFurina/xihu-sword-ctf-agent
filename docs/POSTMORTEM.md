# Post-mortem: our 0-flag contest, and what we changed afterwards

> 中文摘要：本文是 2026-08-21 正式赛 **0 解出** 的复盘**入口与导读**。14 篇**中文原始档案**（未删节）见 [`../deliverables/复盘赛报/`](../deliverables/复盘赛报/)。本文不替代它们——本文是地图，它们是现场记录。
>
> **项目状态**：我们未晋级初赛；本仓库作为**长期开源资产**维护，而不是参赛作品。
>
> **路径约定**：本文中的路径均**相对仓库根**（与两份 README 的"相对 `ctf_agent/`"约定不同，此处刻意如此，避免跨文档歧义）。

---

## 1. Facts (no interpretation)

| 项 | 值 | 来源 |
|---|---|---|
| 赛事 | 2026-08-21，14:00–17:00 | 见下 |
| 结果 | **0 accepted flags** | `README.md` 顶部诚实声明（闸门认可段落） |
| 尝试规模 | 62 次尝试 / 32 道题 | `deliverables/复盘赛报/赛后深度复盘-20260821-正式赛0解出根因与解决方案.md`（**我未独立重算**，原文原始路径已不在工作树，以该文为准） |
| 对照组 | 赛前热身赛 7/7（同源语料） | 同上 |
| 当前离线 KPI | `offline_verified` = **14** / 题库 **92** 题 = **15.2%** | `python ctf_agent/scripts/_kpi_canonical.py` |

**为什么热身赛 7/7 不算数**：热身题与我们本地语料同源（预扫秒解），正式赛 32 题是**未见过的真题**。链路任何一环断掉，结果就是 0 —— 这正是我们要复盘的东西。

---

## 2. Root causes — 结构性，不是调参能救的

按影响排序。**前两条已经修好了，但它们修好的是"可用性"，不是"竞争力"。**

| # | 根因 | 性质 | 状态 |
|---|---|---|---|
| **R1** | **平台数据链路字段错配**：`list_challenges` 只返回 5 个字段，代码假设的 `has_attachment/has_instance` 恒 False → 附件永不下载；`get_access` 真实字段是 `endpoints[].exposeIps[0]`；solver 用 list 阶段空的 `description` 构造题目 → LLM 拿到空题面 | 工程缺陷 | ✅ 已修复并有回归 |
| **R2** | **LLM provider 全失效**：残留 `CTF_AGENT_LLM_BASE_URL` 把 moonshot/ark 请求全部吸到千帆端点 → 401；deepseek 402 余额耗尽；无熔断，坏 provider 持续空转数十分钟 | 工程缺陷 | ✅ 已修复（熔断 + 显式 provider 忽略全局 base_url） |
| **R3** | **题型分类误判**：32 题中 24 题被判为 misc；分类靠标题前缀猜测 → 选错工具包 | 部分工程、部分能力 | ⚠️ 部分修复，**未经真题全量回归** |
| **R4** | **能力缺口（headline）**：本地语料 ≠ 正式赛真题。数据链路修好后依然解不出——这不是 bug，是"确定性优先"定位与"misc 为主体"的题库之间**根上的错位** | **结构性** | ❌ **未修复** |

**R4 的具体形态（可核）**：题库 92 题中 **misc 46 题（50.0%）**是最大的单一类目（crypto 22 / web 13 / reverse 9 / pwn 2），而已验证的确定性解出集中在 crypto 与 reverse。**我们不为单题写求解器，所以这个缺口只能靠增加确定性 skill 弥合，不能靠调参。**

**关于 web / pwn**：严格 KPI 的 14 道解出中**没有 web 解出、也没有 pwn 解出**（白名单见 `ctf_agent/scripts/_antifraud.py` 的 `BASE_AUTHORIZED_KPI_SOLVES` ∪ `PROMOTION_EVIDENCE`）。这类题通常需要靶机实时交互或动态调试，而离线确定性分析器不做这些 —— **这是设计边界，不是待办项**。
⚠️ 但也**不要**把它写成"web/pwn 能力为零"：`ctf_agent/agents/web_toolkit.py` 实际带 SSTI / SQLi / JWT / 反序列化等 fallback payload 模板（源码内可查 `_FALLBACK_SSTI` / `sqli_login_bypass` / `_FALLBACK_JWT`）。**错误的自我贬低与夸大能力一样是失实。**

---

## 3. 我们不声称什么（读任何数字之前先读这一段）

1. 修好 R1–R3 只会让 agent 从**不可用**变成**可用**，不会让它**有竞争力**；我们不声称"修好就能解出"。
2. `offline_verified` 是**绝对计数，不是率**，也不是能力度量：这些题的 writeup 大概率已在 LLM 预训练语料中（污染风险）。
3. 严格 KPI 的 14 道解出**全部来自确定性管线**；LLM 对严格 KPI 的自主推理贡献为 **0**。
4. 一切"解出"都指**离线**对历史真题的确定性分析，**从不代表线上赛事得分**。

---

## 4. 赛后修了什么（证据锚）

| 主题 | 落点 | 证据锚 |
|---|---|---|
| 数据链路与韧性（R1/R2） | `ctf_agent/ctfplatform/dasctf.py`、`ctf_agent/llm/` | 复盘文档载提交 `cf595b2` / `fdf1097` / `7aa601c`（**⚠️ hash 为我转引，未经 git 复核**；请以 `git log` 现验为准） |
| 门禁体系 | 测试 / E2E / 网络 / 密钥 / 写租约 五道，钩子 `ctf_agent/git_hooks/` | `.git/config` 的 `hooksPath`；`ctf_agent/scripts/_scan_secrets.py`、`_lease.py`、`_e2e_verify.py`、`_net_check.py` |
| KPI 反注水 | 只升不降的棘轮 + 晋升必须带证据 | `ctf_agent/scripts/_merge_gate.py`（`count_offline_verified`）、`ctf_agent/scripts/_antifraud.py`（`PROMOTION_EVIDENCE`） |
| 跨文档数字闸门 | README 数字漂移机械拦截 | `ctf_agent/scripts/_doc_consistency.py` |
| 发布闸（凭据红线） | 凭据命中 = FAIL；明文 flag 仅告警 | `ctf_agent/scripts/release_export.py`（`SECRET_PATTERNS`，8 条，只允许追加） |
| KPI 治理史（9→12→13→14） | 每题带 sha256 真值 + 可复现 verifier | `ctf_agent/REAL_SOLVES_LEDGER.md` + `ctf_agent/scripts/_antifraud.py` 白名单（`AUTHORIZED_KPI_SOLVES`） |

**这条不是修复，但是最重要的资产**：我们把"诚实"做成了会失败的代码——KPI 棘轮只升不降、无证据晋升被拒、跨文档数字漂移判红。**本仓库敢公开，靠的是这套机制，不是靠我们的自律声明。**

---

## 5. 口径规则（引用任何数字前必读）

| 口径 | 值 | 说明 |
|---|---|---|
| `offline_verified` | **14** | 绝对计数；全集覆盖率 15.2%（92 题） |
| held-out **能力分母** | **2** | 唯一合法的 LLM 自主推理分母 |
| held-out **可选跑池** | **17** | 2 自有 + 15 道外部 Google CTF 采源；难度显著更高，**抽样跑过的题全部未解出且报告被机器标记 `integrity.interpretable=false`** ⇒ **不是分母** |
| 已作废口径 | 15 题子集 / 86.7%；10 题池 | 10 题池后被确认**受污染**（7 道 WRITEUP 重建题 + 1 道源码泄露 web 题），其 `1/10`、`4/10` 与 566,570 / 696,506 tokens **不得再作能力率引用**（见 `deliverables/复盘赛报/heldout重测-首次真实LLM-20260919.md` 的 2026-09-26 口径更正） |
| 唯一那次 LLM 解出 | `real_crypto_dnui_keyboard`，**1/2** | **单次运行、我们未做重复验证**：同一题在更早的 09-19 两轮中均为 `error=hallucination` 未解出，到 09-22 才由 LLM 解出 ⇒ **不声称可复现、不构成能力承诺**。按我们自己的样本阶梯（8→12→20→30→60），2 个样本只是数据点 |

**两个 held-out 数字不可互除**：工具对不可比集合**恒输出 `coverage_of_heldout = None`**，而不是造一个比率。

---

## 6. 14 篇原始档案导读（按"你想找什么"组织，不按文件名罗列）

**找根因与赛事时间线** → `赛前深度研究报告-20260821-1010.md` → `初赛实战深度复盘-20260821.md`（含 `初赛实战深度复盘-补遗-2题0矛盾.md`）→ `赛时续攻诊断-20260821.md` → **`赛后深度复盘-20260821-正式赛0解出根因与解决方案.md`（最重要，本文 §1–§2 的数据来源）**；另有 `赛后数据分析看板-20260821.html`（可视化）。

**找修复证据与整改验收** → `赛后重锐评-验收记录-20260822.md`；`决赛深度改造-20260821.md`（**标题里的"决赛"已不适用，但内容是一份实打实的代码改造记录**：重型模型触发收敛、firstblood 附件路径修复等，请当工程记录读）。

**找能力与 LLM 实测** → `llm_breaking_ice_rerun_20260901.md`、`honest_bench_first_signal_20260901.md`、`heldout重测-首次真实LLM-20260919.md`（**注意：本文头部有 2026-09-26 口径更正，读它必须先读那段更正**）；另有 `数据分析报告-scene8-20260822.md` 与 `数据分析结论-20260822-整合版.md`。

**⚠️ 一篇已作废，但仍在仓库里** → `明年复赛夺冠作战计划-20260824.md`。**它写于"假设能进决赛"的前提下，而结果是未晋级** —— 之所以不删，是因为"绝不删除任何东西"是本项目的红线。请读作**历史计划**，不要读作当前路线图。

---

## 7. 如何复现（自己验，别信我们）

```bash
cd E:/Program/西湖论剑
python ctf_agent/scripts/_kpi_canonical.py      # offline_verified / real_corpus / heldout_candidates / heldout_runnable_pool
python ctf_agent/scripts/_merge_gate.py         # KPI 棘轮（只升不降）+ 回归集
python ctf_agent/scripts/_doc_consistency.py    # 跨文档数字漂移闸门
python ctf_agent/scripts/release_export.py --scan-only   # 发布闸：凭据 0 命中才放行
```

KPI 真值与台账：`ctf_agent/REAL_SOLVES_LEDGER.md`、白名单 `ctf_agent/scripts/_antifraud.py`。
held-out 实测原始报告：`ctf_agent/heldout_evidence/benchmark_report_clean2_20260922_deepseek.json`（`mode=real_main_agent`，`ctf_agent/heldout_evidence/PROVENANCE.md` 给出 sha256 可自校验）。

> 明文 flag **不做脱敏**——它们是验证器的比对期望值；为发布而脱敏等于拆掉"machine-verified"的地基。**唯一硬红线是凭据**（API key / token / 私钥）。
