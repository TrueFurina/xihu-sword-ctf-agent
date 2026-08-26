# 西湖论剑 CTF-Agent · xihu-sword-ctf-agent

> 一个 **deterministic-first（确定性优先）** 的多智能体 CTF 解题框架。
> A deterministic-first multi-agent framework for solving CTF challenges.

[English](#english) · [中文](#chinese)

---

<a id="chinese"></a>
## 中文

### 它解决什么问题

多数「CTF 解题智能体」只是「LLM 套一层 shell」：结果不可复现、不可调试、还容易夸大能力。
我的核心判断是——CTF 里大量题型（RSA 攻击、隐写提取、源码审计、多层编码）本质是可穷举的**确定性套路**，不该交给会幻觉的 LLM。

所以本项目只回答一个问题：**如何让解题系统「可复现、可审计、且对能力水位诚实」**。

### 设计取舍（本项目最大的判断）

采用 **deterministic-first**：先跑 `presolve` 静态分析层，并行扇出一群确定性技能；只有静态分析 miss 的题，才升级给 LLM，且 LLM 处在「白名单 provider + token 预算 + 墙钟止损」三重约束之后。
这与「LLM-first」路线相反，是本项目最核心的取舍。

### 系统结构（多智能体分工）

```
                         ┌──────────────┐
      题面/附件 ───────▶ │  supervisor  │  步骤预算 + 工具优先纪律 + 提交闸门(fail-closed)
                         └──────┬───────┘
                                │ 静态分析优先
                 ┌──────────────┼───────────────────────┐
                 ▼              ▼                        ▼
         ┌────────────┐  ┌──────────────┐        ┌──────────────┐
         │  presolve  │  │  解题 agents  │        │  math_engine │
         │ 静态分析器  │  │ crypto/misc/ │        │  数学推理补充  │
         │ 49 确定性技能│  │ web/rev/pwn  │        └──────────────┘
         └─────┬──────┘  └──────────────┘
               │ miss 才升级
               ▼
         ┌────────────┐
         │    LLM     │  白名单 + token 预算 + 墙钟止损
         └────────────┘
```

监督者（supervisor）负责步骤预算与「工具优先」纪律；五类解题 agent 各管一类题型；
底层 `math_engine` 补数学推理。提交走 **fail-closed 闸门**——请求出错即硬失败，绝不带病提交。

### ⚠️ 诚实水位声明（请务必读）

本项目坚持「工件可信、裁判分离、启动即门禁」三铁律，对能力水位也保持克制：

| 口径 | 数值 | 说明 |
|---|---|---|
| 真题集（历年 CTF）真链路实测 | 15/15 由 **presolve 静态分析直出** | 这是**工具链覆盖率**，不是 LLM 能力 |
| 主 Agent（LLM）真题集真实推理解出 | **0** | 未证明「LLM 推理不行」，只证明「尚未验证」 |
| 真实赛场线上 accepted | **0** | 诚实记录，不虚报 |
| 确定性技能数量 | **49** | 可复跑、可审计的 `run(params)->dict` 接口 |

**结论很克制**：本系统的能力 = 静态分析器覆盖率；要扩题型，就写更多确定性技能。我们**没有**用 mock 正确率、自建靶机得分等「虚高数字」充当战绩。

### 快速开始

```bash
bash setup.sh                 # 建 .venv + 装依赖 + 白名单预检 + 全测试
python run.py --mode mock     # 离线冒烟演示（不烧 token）
python -m pytest tests/ -q -m "not slow"   # 离线测试门禁
```

题库位于 `data/questions_real/`（flag 字段已自动脱敏为 `<redacted>`）。

### 治理与边界

- **工件可信**：只信可复现命令 + 落盘工件；不把 LLM 自述当事实。
- **裁判分离**：实现者不能当自己的裁判（诚实扫描器 `_honesty_scan` 拦截虚假水位表述）。
- **隐私边界**：真 flag 全部脱敏；密钥只走环境变量与白名单 provider；pre-commit 钩子扫描明文密钥。
- 内部赛题资源、作战复盘、未脱敏报告**不在本仓库**（由发布脚本自动剔除）。

### 路线图

见 [Issues](https://github.com/truefurina/xihu-sword-ctf-agent/issues) —— 已开 8 条真实工程路线图（path_traversal 自动解、E1 结构化输出、E8 多候选提交、reverse 工具链重接、诚实水位 CI、SSRF fallback、扩大确定性技能、离线 demo 文档）。

---

<a id="english"></a>
## English

### What problem it solves

Most "CTF-solving agents" are just an LLM wrapped in a shell — non-reproducible,
undebuggable, and prone to overclaiming. Our core thesis: a large share of CTF
challenges (RSA attacks, stego extraction, source audit, layered encoding) are
**deterministic patterns** that should not be handed to a hallucinating LLM.

This project answers one question only: **how to make a solving system
reproducible, auditable, and honest about its real capability level.**

### Key design choice: deterministic-first

A `presolve` static-analysis layer fans out 49 deterministic skills first. Only
challenges it misses are escalated to the LLM, which is then boxed by whitelisted
providers + a token budget + a wall-clock stop-loss. This is the opposite of an
"LLM-first" approach and is the project's central trade-off.

### Honesty disclaimer (read this)

| Metric | Value | Note |
|---|---|---|
| Real past-CTF set, true-chain | 15/15 solved by **presolve static analysis** | tooling coverage, **not** LLM capability |
| Main Agent (LLM) true solves on real set | **0** | "not validated", not "proven incapable" |
| Live competition accepted | **0** | reported honestly |
| Deterministic skills | **49** | auditable `run(params)->dict` |

We deliberately avoid presenting mock accuracy or self-hosted target scores as
real capability.

### Quick start

```bash
bash setup.sh
python run.py --mode mock
python -m pytest tests/ -q -m "not slow"
```

### License

[MIT](LICENSE) — Copyright (c) 2026 truefurina (张敏杰 / Zhang Minjie).
