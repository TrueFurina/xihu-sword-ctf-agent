# 西湖论剑 AI-Agent 自动解 CTF 夺旗赛 · 深度调研报告

> 调研日期：2026-08-10 ｜ 调研对象：第九届西湖论剑·中国杭州网络安全技能大赛「AI Agent 解题夺旗」赛制
> 调研目标：为自研「多题并发、速度碾压」的 AI-CTF-Agent 系统提供开发前全维度参考
> 调研原则：仅依据检索到的官方/原始网页内容；未查到明确依据处一律标注「未查到官方说明」；关键结论附来源链接
> 适用范围：本项目（西湖论剑 AI-Agent 赛道冲第一定向）

---

## 一、赛事深度调研总结

### 1.1 赛事基本信息（第九届，2026）

| 项目 | 内容 | 来源 |
|---|---|---|
| 赛事全称 | 第九届西湖论剑·中国杭州网络安全技能大赛 | [杭州网 hznews](https://hznews.hangzhou.com.cn/jingji/content/2026-07/14/content_9254726.htm)（2026-07-14） |
| 主题 | 人才：引领 AI 安全新范式 | 同上 |
| 主办/指导 | 杭州市公安局、共青团杭州市委、杭州市学生联合会指导；安恒信息、杭州市网络安全协会主办；阿里云为 AI 合作单位 | [信息安全知识库 gm7.org 转载官方公告](https://www.gm7.org/archives/131915)（2026-07-20） |
| 性质 | 纯公益性网络安全赛事，面向全国高校学子 | 同上 |
| 总奖金 | 超 30 万元 | 同上 |
| 报名官网 | game.gcsis.cn | 同上 |
| 报名时间 | 2026-07-13 10:00 ～ 08-10 16:00 | 同上 |

### 1.2 本届最大变化：首次引入「AI Agent 解题夺旗」赛制

官方公告明确的三条赛制核心特征（来源：[杭州网](https://hznews.hangzhou.com.cn/jingji/content/2026-07/14/content_9254726.htm)、[官方公告转载 gm7.org](https://www.gm7.org/archives/131915)）：

1. **题量远超人工处理上限**——选手必须借助 Agent 进行批量分析、自动尝试与持续迭代；
2. **仅开放 API 接口，不提供传统网页端答题入口**——重点考验选手的系统架构设计与工程化能力；
3. **支持人机持续交互**——选手可设定目标、调整优先级、修正执行策略。

官方评判导向原文（来源同上）：
> 「大赛的核心评判标准，不再只是『选手网安能力的强弱』，而是『谁能将人的安全基础能力沉淀为 AI Agent 的系统能力』——解题主体是 AI，人的核心价值在于构建 Agent、制定战略并监督过程，考验的是工程化实现与 AI 编排能力，而非个人手工解题技巧。」

### 1.3 赛程与晋级规则（官方公告原文数据）

| 环节 | 时间 | 说明 | 来源 |
|---|---|---|---|
| 报名启动 | 2026-07-13 10:00 | — | [gm7.org](https://www.gm7.org/archives/131915) |
| 报名截止 | 2026-08-10 16:00 | — | 同上 |
| 测试赛 | 08-18 09:00 ～ 08-19 17:00 | 熟悉平台、调试 API | 同上 |
| 线上初赛 | 08-21 14:00 ～ 17:00 | 线上形式 | 同上 |
| 晋级名单公布 | 08-31 前 | 初赛综合成绩前 12 名晋级线下决赛 | 同上 |
| 线下决赛答辩 | 09 月底前 | 现场系统演示 + 专家组代码审查与技术问答 | 同上 |

**决赛要求（官方原文）**：晋级队伍需进行现场系统演示，并接受专家组的代码审查和技术问答，全面展示团队在 AI Agent 设计、工程落地与攻防实战中的综合能力（来源：[gm7.org](https://www.gm7.org/archives/131915)）。

### 1.4 奖项与福利设置

| 奖项/福利 | 内容 | 来源 |
|---|---|---|
| 奖项结构 | 一等奖 1 名、二等奖 2 名、三等奖 3 名、优胜奖 6 名，颁发奖金、奖牌及荣誉证书 | [gm7.org](https://www.gm7.org/archives/131915) |
| 实习直通 | 晋级决赛队伍成员获安恒信息实习生优先录用资格 | 同上 |
| 竞赛合伙人 | 晋级成员成为「安恒数字人才创研院」竞赛业务合伙人 | 同上 |
| 认证培训 | 初赛前 30 名队伍成员/指导老师获 CISAW-LPT 或 CCRC-CSERE 培训名额（二选一，免培训费） | 同上 |
| 基础证书 | 初赛前 50 名队伍成员直接获安恒认证基础工程师（DCSA）证书 | 同上 |
| 算力支持 | 参赛大学生每人 300 元阿里云算力资源；高校教师/科研团队每人 5 折算力；开放百炼平台、QoderWork、秒悟 AI 工具 | [gm7.org](https://www.gm7.org/archives/131915)、[宙飒天下 zhousa.com](http://zhousa.com/archives/93695.html) |

### 1.5 往届赛事与题型脉络（可作题型预判依据）

- 赛事自 2017 年创办，已走过 8 年；累计参赛人次突破 21000、战队超 5000 支、覆盖近 700 所高校（来源：[杭州网](https://hznews.hangzhou.com.cn/jingji/content/2026-07/14/content_9254726.htm)）。
- 第八届（2025 年 3 月 29 日决赛）：436 所高校、842 支战队、4169 名选手；北京邮电大学「天枢 Dubhe」战队获网络攻防实战赛冠军；赛题涵盖「AI+安全」、数据安全、IoT 漏洞挖掘、大模型内容仿写、基于 AI 的数据分析、AI 基础设施安全（来源：[安恒信息官网](https://www.dbappsecurity.com.cn/content/details4756_30609.html)）。
- 第八届初赛数据：420 所高校、758 支战队、3960 人（来源：[第八届初赛官方 WriteUp（下）CN-SEC](https://cn-sec.com/archives/3670488.html)）。
- 第八届初赛 Pwn 题型参考：共 3 题（栈上任意地址写、shellcode、另一题）；Crypto 出现 matrixRSA 等（来源：[返璞归真 blog](https://blog.xxxb.cn/CTF/WriteUp/2025/WestLake2025.html)、[Ya1orin](https://ya1orin.github.io/post/%E7%AC%AC%E5%85%AB%E5%B1%8A%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%91-%E5%88%9D%E8%B5%9B/)）。

### 1.6 API 答题协议、并发上限与频率限制

- **未查到官方公开的 API 协议细节**（openapi 文档、并发上限、请求频率限制、提交频率限制均未在官方公告/官网公开页面中查到）。官方仅披露「测试赛供选手熟悉平台和调试 API」「仅开放 API 接口」（来源：[gm7.org](https://www.gm7.org/archives/131915)）。
- 参考线索：GitHub 开源项目 [o0x1024/aiagentsec-benchmarks](https://github.com/o0x1024/aiagentsec-benchmarks/blob/main/docs/agent-operator.md) 描述了一类 AI-Agent CTF 平台控制面 API 的通用模式（非西湖论剑官方，仅供架构预研参考）：`GET /openapi.json` → `GET /api/challenges` → `GET /api/challenges/{id}` → `POST /api/hint`（可选）→ `POST /api/start_challenge` → 自主解题 → `POST /api/submit` → `POST /api/stop_challenge`；使用 `Agent-Token` 请求头认证；该文档同时给出 agent 执行约束建议（一次只处理一题、提交前做 flag 格式检查、成功后主动停止题目、失败记录原因后切下一题、不要直接操作 Docker/VM 宿主机）。⚠️ 该文档非西湖论剑官方发布，仅作为平台交互模式的一般性参考。

### 1.7 容易翻车的现场故障清单（基于官方赛程/规则可推断项 + 第三方描述）

- 决赛需要「现场系统演示 + 代码审查 + 技术问答」——若系统架构混乱、无法现场跑通、答辩讲不清设计，会被直接扣分（官方要求：[gm7.org](https://www.gm7.org/archives/131915)）。
- 初赛 8-21 仅 3 小时（14:00–17:00），题量「远超人工处理上限」——若 Agent 无法并发、单题串行排队，将大面积欠解（官方：[gm7.org](https://www.gm7.org/archives/131915)）。
- 测试赛 8-18/19 仅两天，若 API 适配脚本未提前就绪，正式赛将手忙脚乱。
- 「未查到官方说明」项：答辩 PPT 模板、交付物清单、环境部署要求、安全限制（是否允许外网、是否限制模型调用次数等）——官方公开页面未披露，需等测试赛/官网后续公告。

---

## 二、开源竞品对比表以及竞品致命短板清单

> 说明：以下均为 GitHub / 官方论文 / 官方博客可查证的信息；「未查到官方说明」处均为该项目的公开页面中未披露的内容。

### 2.1 竞品逐个分析

#### ① CTF-Agent（verialabs/ctf-agent）
- **定位**：自动 CTF 求解器，**并行竞速多个 AI 模型**；官方自述获 **BSidesSF 2026 CTF 第一名，52/52 全解**。
- **编程语言**：Python 3.14+，使用 `uv` 管理（[README](https://github.com/verialabs/ctf-agent)）。
- **任务处理模式**：**并发**——coordinator LLM 管理整场，solver swarm 分组并行攻击各题，每题同时跑多个模型，先拿到 flag 者胜（[README](https://github.com/verialabs/ctf-agent)）。
- **支持题型**：README 未限定题型（未查到官方说明）；面向 CTFd 平台实例。
- **工具调用方式**：每个 solver 在独立 Docker 容器内运行，预装 CTF 工具；coordinator 读取 solver 轨迹并下发针对性指引；solver 间通过 message bus 共享发现（[README](https://github.com/verialabs/ctf-agent)）。
- **默认模型阵容**：Claude Opus 4.6 (medium/max)、GPT-5.4、GPT-5.4-mini、GPT-5.3-codex（[README](https://github.com/verialabs/ctf-agent)）。
- **短板**：README 未披露成本控制、限流处理与单题超时策略（未查到官方说明）；「周末开发」属性意味着工程化打磨有限；强依赖 CTFd 平台协议，与西湖论剑自定义 API 需适配。

#### ② llm-ctf-agent（greyhatgt/llm-ctf-agent-boilerplate）
- **定位**：Docker 化 LLM-CTF-Agent 脚手架，面向教学/评测（Fall 2025 LLM CTF Agent Project）。
- **编程语言**：Python；通过 LiteLLM 兼容 API 接入任意模型（[README](https://github.com/greyhatgt/llm-ctf-agent-boilerplate)）。
- **任务处理模式**：**串行**——`SimpleAgent.solve_challenge()` 逐题求解，批量评测时逐题执行（未查到官方并发说明）。
- **支持题型**：文件型 + 网络型（多容器服务）自动检测（[README](https://github.com/greyhatgt/llm-ctf-agent-boilerplate)）。
- **工具调用方式**：Docker 容器隔离、每题独立网络；自动发现服务；LLM 成本/请求追踪（[README](https://github.com/greyhatgt/llm-ctf-agent-boilerplate)）。
- **短板**：定位是「boilerplate 脚手架」，策略实现（solve_challenge 方法）需自行开发；串行执行，无并发提速能力。

#### ③ Reynard
- **检索结论**：GitHub 上名为 Reynard 的项目（reynard-testing/reynard、entropy-tamer/reynard-tool-calling、TechCPT/Reynard）均与 CTF 自动解题无关（分别是微服务故障注入测试工具、TS 工具调用系统、Discord bot）。**未查到名为 Reynard 的成熟 AI-CTF-Agent 开源项目**（来源：[reynard.dev](https://www.reynard.dev/)、[github.com/reynard-testing/reynard](https://github.com/reynard-testing/reynard)）。

#### ④ NYU-CTF-Bench（NYU-LLM-CTF/NYU_CTF_Bench）
- **定位**：**基准数据集**（非求解器）——200 道 CSAW CTF 题（test 集）+ 55 道开发集，覆盖 web / pwn / forensics / rev / crypto / misc 六类（[GitHub](https://github.com/nyu-llm-ctf/nyu_ctf_bench)、[官网](https://nyu-llm-ctf.github.io/)）。
- **论文**：NeurIPS 2024《NYU CTF Bench: A Scalable Open-Source Benchmark Dataset for Evaluating LLMs in Offensive Security》（[arXiv](https://arxiv.org/html/2406.05590)）。
- **要点**：题目全部 dockerized，便于自动化框架交互；是评测 LLM 智能体攻防能力的事实标准之一。
- **短板（论文自述）**：类别分布不均衡（rev/crypto/pwn/misc 多，forensics/web 少）；仅来自 CSAW 单一赛源；模型有时会用错工具（如用 C/C++ 逆向工具处理 Python 代码）（[arXiv](https://arxiv.org/html/2406.05590)）。

#### ⑤ D-CIPHER（NYU-LLM-CTF/nyuctf_agents）
- **定位**：**多智能体** CTF 求解框架：Planner（总体规划）+ 多个异构 Executor（分任务执行）+ Auto-prompter（自动生成初始提示）（[arXiv 2502.10931](https://arxiv.org/html/2502.10931)）。
- **编程语言**：Python，Docker 环境（[GitHub](https://github.com/NYU-LLM-CTF/nyuctf_agents)）。
- **成绩（论文官方数据）**：NYU CTF Bench 22.0%、Cybench 22.5%、HackTheBox 44.0%，比此前最优高 2.5–8.5 个百分点；解决的 MITRE ATT&CK 技术多 65%（[arXiv](https://arxiv.org/html/2502.10931)）。
- **短板**：论文明确承认单智能体在复杂 CTF 上「retries、loss of focus、hallucinations」，多智能体改善但仍依赖单轮循环效率；绝对解出率仍低（22%），说明对难题的覆盖面有限（[arXiv](https://arxiv.org/html/2502.10931)）。

#### ⑥ InterCode-CTF（princeton-nlp/intercode）
- **定位**：把 CTF 建模为**交互式编码任务**的基准与执行环境（Bash 动作空间 + Docker 执行反馈）；论文《Language Agents as Hackers: Evaluating Cybersecurity Skills with Capture the Flag》（Yang et al. 2023）（[GitHub](https://github.com/princeton-nlp/intercode/tree/master/data/ctf)、[NeurIPS](https://papers.neurips.cc/paper_files/paper/2023/file/4b175d846fb008d540d233c188379ff9-Paper-Datasets_and_Benchmarks.pdf)）。
- **任务处理模式**：串行 ReAct 循环（思考→动作→观察）。
- **成绩**：基线 40%（40/100）；后续 ReAct&Plan@5 达 95%（81/85）——其中 General Skills 100%、Reverse 96%、Crypto 93%、Forensics 91%、Pwn 100%、Web 100%（[InterCode 实验记录](https://intercode-benchmark.github.io/#ctf)）。
- **短板**：作者自述该基准（高中难度）已被「饱和」，需转向 NYU-CTF、3CB、HackTheBox 等更难的题集；早期模型成绩被证明低估（[InterCode 记录](https://intercode-benchmark.github.io/#ctf)）。

#### ⑦ SageCTF（OpenSage 团队）
- **定位**：基于自编程 Agent 框架 OpenSage 的 CTF 特化智能体，UC Santa Barbara / UC Berkeley 团队开发。
- **成绩（官方博客）**：DEF CON CTF 2026 资格赛以单人身份解出 7 道难题、8 个 flag、1743 分，位居全部 686 支计分队伍**前 5%**；50 题对比评测中 **39/50** vs Claude Code **13/50**，Claude Code 解出的题全部被 SageCTF 覆盖（[OpenSage 官方博客](https://www.opensage-agent.ai/blog/sagectf.html)）。
- **架构创新**：AI 自生成拓扑（而非预设工作流）、智能体间通信、层级记忆、多模型编排（[官方博客](https://www.opensage-agent.ai/blog/sagectf.html)）。
- **短板**：每解一题平均耗时 **5 小时**（最长的 12 小时），速度极慢——不符合「多题并发、速度碾压」的赛事目标；依赖 DEF CON 赛制特点（不允许自动提交，只验证解题能力）（[官方博客](https://www.opensage-agent.ai/blog/sagectf.html)）。

#### ⑧ CHYing-Agent
- **定位**：国内实战项目（剑仙SEC 开发者主导，腾讯云黑客松智能渗透挑战赛），「双 Agent 协作 + 动态角色互换」。
- **架构**：顾问 Agent（战略层，只在任务开始/连续失败 3 次/第 5、10、15 次尝试时介入）+ 主攻手 Agent（执行层，独立快速迭代）；极简三层工具体系：Docker 挂载 Kali 真环境 + Python 沙箱 + 常规 API 工具（[腾讯云开发者社区](https://developer.cloud.tencent.com/article/2650350)）。
- **成绩**：Day1 版本排名第 4，收盘第 8；演进后单日最高解 15 题（上午 7 + 下午 8），最终线上总成绩第 9（[腾讯云开发者社区](https://developer.cloud.tencent.com/article/2650350)）。
- **短板**：初始「豪华多 Agent + 自建工具」架构过重，开赛前夜被迫推翻重做——提示复杂工具链带来认知超载与逻辑死锁风险；对 KPT 竞速目标而言单日 15 题仍有提升空间。

#### ⑨ Cyber-AutoAgent（westonbrown）
- **定位**：自主渗透测试 + CTF 的通用 agent，基于 Strands 框架，支持 AWS Bedrock / LiteLLM / Ollama（[GitHub](https://github.com/westonbrown/Cyber-AutoAgent)）。
- **成绩**：XBOW 评测基准 **84.62%**（88/104），较 v0.1.1 的 76% 提升 8.62 个百分点（[官方 Discussion #41](https://github.com/westonbrown/Cyber-AutoAgent/discussions/41)）。
- **状态**：**仓库已归档（read-only）**——作者自述「实验性副业项目」需要全职投入才能达到生产级（[GitHub](https://github.com/westonbrown/Cyber-AutoAgent)）；截至检索时点约 534 stars（[GitHub 用户页](https://github.com/westonbrown)）。
- **短板（官方失败模式分析）**：已知失败模式包括 JWT secret 发现后无法推断 payload 结构、缺少 CTF 专属 bucket 字典、通用框架稀释了特定攻击模式能力（XSS/IDOR/SSTI 等）（[Discussion #41](https://github.com/westonbrown/Cyber-AutoAgent/discussions/41)）。

#### ⑩ AutoCTF（eternaldooly/AUTOCTF）
- **定位**：个人 CTF 猎题环境：React/Vite 前端 + Node.js 后端 + Codex + MCP（IDA、Volatility 集成），WSL2 运行（[GitHub](https://github.com/eternaldooly/AUTOCTF)）。
- **任务处理模式**：未查到官方并发说明（个人工具型项目）。
- **短板**：强依赖本机 Codex 登录与 WSL2/Windows 桥接环境，非可部署的多题并发系统；面向个人解题而非赛事竞速。

#### 补充竞品（调研中发现的相关项目）
- **hydra（iamkorun）**：自主 CTF 批量求解器——每题独立 Docker + Claude Code，triage agent 分类后派发 7 个专家子 agent，~30 个攻击模式 playbook（RSA/ECC/padding-oracle/LFI-to-RCE/prototype-pollution/volatility/anti-debug）；三层监督（operator babysit LLM 监督 + 确定性 watchdog 边车 + pre-commit flag gate）；支持 pass@k 并行尝试（[GitHub](https://github.com/iamkorun/hydra)）。**值得重点参考其 watchdog/flag gate 设计。**
- **LLM-CTF-Solver（gehewu）**：基于 BUUCTF_Agent 二次开发，ReAct 范式 + 三层解析回退 + 六维僵局检测 + 三层记忆 + RAG 知识库；CTF/渗透双模式；内置 20+ 安全工具（crypto_attacks、stego_tools、reverse_tools 等）（[GitHub](https://github.com/gehewu/LLM-CTF-Solver)）。
- **CoRedteam-CTF**：两阶段多智能体（审计→利用），Docker 沙箱 + ChromaDB 长期记忆 + 双模型 Reflexion 架构（[GitHub](https://github.com/CorruptingHeart-Y/CoRedteam-CTF)）。

### 2.2 竞品优缺点对比表

| 项目 | 语言 | 任务模式 | 支持题型 | 工具调用 | 官方成绩 | 核心短板 |
|---|---|---|---|---|---|---|
| CTF-Agent (verialabs) | Python | **并发**（多模型竞速） | 未限定（CTFd 平台） | Docker + coordinator 消息总线 | BSidesSF 2026 第 1 名（52/52） | 成本/限流策略未披露；依赖 CTFd 协议 |
| llm-ctf-agent (greyhatgt) | Python | 串行 | 文件型+网络型 | Docker + LiteLLM | 未披露 | 脚手架属性，无并发、无策略 |
| Reynard | — | — | — | — | — | **未查到对应 CTF 开源项目** |
| NYU-CTF-Bench | 数据集 | — | 6 类（200+55 题） | Docker | 基准事实标准 | 类别失衡、单一赛源、工具误用（论文自述） |
| D-CIPHER | Python | 多智能体（planner+executor） | 6 类 | Docker | NYU 22.0% / Cybench 22.5% / HTB 44.0% | 绝对解出率低、单轮循环效率不足 |
| InterCode-CTF | Python | 串行 ReAct | 6 类 | Docker bash | 基线 40%→95%（ReAct&Plan） | 难度已饱和，需更难题集 |
| SageCTF | OpenSage | 长时程自治（AI 生成拓扑） | 广（DEF CON 级） | 自编程 + 层级记忆 | DEF CON 前 5%（39/50 vs Claude Code 13/50） | **每题平均 5 小时，速度是致命短板** |
| CHYing-Agent | Python | 双 Agent（顾问+主攻手） | 广（Kali 真环境） | Kali 直挂 + Python 沙箱 | 线上第 9；单日最高 15 题 | 初始架构过重被迫重构；并发深度有限 |
| Cyber-AutoAgent | Python | 串行迭代 | 通用+CTF | Strands 框架 | XBOW 84.62%（88/104） | **已归档停止维护**；通用框架稀释专精能力 |
| AutoCTF | TS/Node | 未披露 | 个人猎题 | Codex + MCP(IDA/Volatility) | 未披露 | 个人工具型，非并发系统 |
| hydra (补充) | Python/Claude | **并发批量**（pass@k） | 6 类（7 子 agent） | Docker + 30 playbook | 未披露 | 依赖 Claude Code 生态 |
| LLM-CTF-Solver (补充) | Python | ReAct 串行 | 6 类 | 20+ 内置工具 | 未披露 | 非并发 |

### 2.3 竞品致命短板清单 → 我的项目差异化创新点

1. **速度短板（SageCTF 平均 5h/题；InterCode/D-CIPHER 串行循环）** → 我的创新点：**多题并发 + 每题多模型竞速**（参考 CTF-Agent 的 swarm 思路但工程化更彻底），毫秒级测速埋点。
2. **成本失控（CTF-Agent 未披露；Cyber-AutoAgent 有 token 追踪但已停更）** → 创新点：**模型分级路由 + 上下文缓存 + 预算熔断**（参考 hydra 的 cost-cap watchdog）。
3. **死循环/僵局（D-CIPHER 论文自述 retries/loss of focus；CHYing 重构教训）** → 创新点：**确定性 watchdog + 六维僵局检测 + 失败日志回传纠错**（参考 hydra 三层监督 + LLM-CTF-Solver 六维僵局检测）。
4. **flag 误报污染（hydra 的 flag gate 值得借鉴）** → 创新点：**pre-commit flag 校验门**（格式/来源溯源/铁证检测），防止把假 flag 提交出去浪费提交额度。
5. **通用框架稀释专精（Cyber-AutoAgent 官方失败分析；NYU 论文工具误用）** → 创新点：**五大题型专属子 Agent + 题型分类器**，每类配专属工具链与提示词模板（Web/Crypto/Reverse/Pwn/Misc 分别特化）。
6. **无可视化（多数项目无面板）** → 创新点：**实时可视化监控面板**（Grafana Live WebSocket 推送），现场演示杀手锏。

---

## 三、CTF 赛题资源分类和高频解题工具、模板清单

### 3.1 西湖论剑历年真题（官方/社区 WriteUp 源）

| 资源 | 说明 | 来源 |
|---|---|---|
| 第八届初赛官方 WriteUp（上） | 组委会官方发布 | [ctfiot.com](https://www.ctfiot.com/225639.html) |
| 第八届初赛官方 WriteUp（下） | 组委会官方发布 | [cn-sec.com](https://cn-sec.com/archives/3670488.html) |
| 第八届初赛个人题解（全方向） | Web/Pwn/Crypto 等 | [Luoingly's Space](https://luoingly.top/post/gcsis-s8-quals-writeup/) |
| 第八届初赛 Pwn 篇 | VPwn / Heaven's door | [返璞归真 blog](https://blog.xxxb.cn/CTF/WriteUp/2025/WestLake2025.html) |
| 2025 西湖论剑 Writeup | CN-SEC 收录 | [cn-sec.com](https://cn-sec.com/archives/3647997.html) |

### 3.2 强网杯历年真题（GitHub 附件仓库）

| 年份/届次 | 仓库 | 来源 |
|---|---|---|
| 2018 强网杯题目整理 | jas502n/2018-QWB-CTF（Misc4/Crypto5/Reverse7/Web9/PWN12） | [GitHub](https://github.com/jas502n/2018-QWB-CTF) |
| 2023 第七届强网杯 | CTF-Archives/2023-qwbs7 | [GitHub](https://github.com/CTF-Archives/2023-qwbs7) |
| 2024 第八届强网杯 | CTF-Archives/2024-qwbs8（附件在 Release） | [GitHub](https://github.com/CTF-Archives/2024-qwbs8) |
| 2025 第九届强网杯线上赛 | CTF-Archives/2025-qwbs9-quals | [GitHub](https://github.com/CTF-Archives/2025-qwbs9-quals) |
| 2025 第九届强网杯线下赛 | CTF-Archives/2025-qwbs9-final | [GitHub](https://github.com/CTF-Archives/2025-qwbs9-final) |
| 2025 强网杯 WriteUp | N0wayBack | [cn-sec.com](https://cn-sec.com/archives/4594063.html) |

### 3.3 picoCTF（CMU，教学型，适合 Agent 训练基线）

- 官方练习场：play.picoctf.org；历年赛题解集：picoCTF Solutions（2019–2026，按年分页）[picoctfsolutions.com](https://picoctfsolutions.com/events)。
- GitHub 题解仓库：PS-003R32/picoCTF（2019–2025 全分类题解）[GitHub](https://github.com/PS-003R32/picoCTF)；Cajac/picoCTF-Writeups（250+ 篇）[GitHub](https://github.com/Cajac/picoCTF-Writeups)；htpa-tsa/picogym（按类别文档化）[GitHub](https://github.com/htpa-tsa/picogym)。
- 题型分类（picoCTF 官方分类）：Web Exploitation、Cryptography、Reverse Engineering、Forensics、General Skills、Binary Exploitation（[picogym](https://github.com/htpa-tsa/picogym)）。

### 3.4 全国大学生信息安全竞赛（CISCN / 长城杯）

- 2024 第十七届 CISCN 初赛：CTF-Archives/2024-CISCN-Quals（含 asm_re、androidso_re、rust_baby、gostack、ezbuf、sanic、Simple_php、easycms、ezrsa、古典密码等题）[GitHub](https://github.com/CTF-Archives/2024-CISCN-Quals)。
- 2024 第十八届暨第二届长城杯：CTF-Archives/2024-CCB-CISCN-Quals（A1natas 战队题解）[GitHub](https://github.com/CTF-Archives/2024-CCB-CISCN-Quals)。
- 2025 第十九届暨第三届长城杯（含 AI 安全方向题「欺诈猎手的后门陷阱」）：CTF-Archives/2025-CCB-CISCN-Quals [GitHub](https://github.com/CTF-Archives/2025-CCB-CISCN-Quals)。
- 历年 CISCN writeup 汇总（2021/2020/2019/2017）：[博客园 Hardworking666](https://www.cnblogs.com/Hardworking666/p/17374801.html)。

### 3.5 五大题型高频漏洞、算法、隐写手段与 EXP 模板（依据检索到的资料）

> 以下内容主要来源于 picoCTF 题解汇总与多篇官方/社区 writeup 的归纳，非赛事官方指定清单；作为预研方向使用。

| 题型 | 高频考点（检索到） | 常用工具/手段 | 来源 |
|---|---|---|---|
| Web | SQL 注入、SSTI（Jinja2/Flask）、PHP 反序列化（__wakeup/__destruct、phar://）、前端校验绕过、目录遍历、文件上传 | Burp Suite、sqlmap、curl/requests、浏览器 DevTools；`{{7*7}}` 探测模板注入 | [CSDN picoCTF 题解汇总](https://wenku.csdn.net/doc/37ioj8i52bkg) |
| Crypto | 古典密码（凯撒/Vigenère/栅栏）、RSA（共模、小指数、n 分解、GCD 共享素数）、AES-ECB 块特征、哈希长度扩展、弱盐 | Python（pycryptodome）、RsaCtfTool、CyberChef、factordb | [CSDN picoCTF 题解汇总](https://wenku.csdn.net/doc/37ioj8i52bkg)、[gm7.org Cursor+MCP CTF 智能体](https://www.gm7.org/archives/13382) |
| Reverse | 字符串比较、TLS 回调反调试、Wasm 逆编译、Android so 逆向、Python 字节码 | IDA Pro / Freeware、Ghidra、x64dbg、JADX、wabt（wasm2wat）、uncompyle6 | [CSDN picoCTF 题解汇总](https://wenku.csdn.net/doc/37ioj8i52bkg)、[NYU-CTF-Bench 论文工具集](https://arxiv.org/html/2406.05590) |
| Pwn | 栈溢出（ret2libc）、任意地址写、shellcode、堆利用、格式化字符串 | pwntools、checksec、ropper、gdb/pwndbg、ROPgadget；流程 checksec→ropper→pwntools | [gm7.org Cursor+MCP CTF 智能体](https://www.gm7.org/archives/13382)、[第八届西湖论剑 Pwn 篇](https://blog.xxxb.cn/CTF/WriteUp/2025/WestLake2025.html) |
| Misc | 隐写（LSB、PNG chunk）、压缩包伪加密/CRC32、流量分析（DNS 隧道、文件提取）、磁盘镜像/内存取证 | binwalk、Stegsolve、Wireshark、Volatility、zipfile 修复脚本、strings/foremost | [CSDN picoCTF 题解汇总](https://wenku.csdn.net/doc/37ioj8i52bkg)、[AUTOCTF（IDA/Volatility MCP）](https://github.com/eternaldooly/AUTOCTF) |

**Agent 训练/评测题源推荐组合**：本地题库用 NYU-CTF-Bench（200 题 dockerized，官方提供，[GitHub](https://github.com/nyu-llm-ctf/nyu_ctf_bench)）+ Cybench（40 题专业级，4 个赛事，[官网](https://cybench.github.io/index.html)）；难度由浅入深：picoCTF → InterCode-CTF → NYU-CTF-Bench → 西湖论剑/强网杯历年真题。

---

## 四、大模型 API 选型方案、备用接口策略

### 4.1 主流大模型 API 官方参数对比（2026-08 检索时点）

| 模型 | 官方上下文 | 官方输入价（每 1M token） | 官方输出价（每 1M token） | 官方特色 | 来源 |
|---|---|---|---|---|---|
| DeepSeek V4-Pro | 1M（官方默认） | $0.435（缓存命中 $0.003625） | $0.87 | 1.6T 总参/49B 激活；OpenAI/Anthropic 双兼容；thinking 开关；reasoning_effort；**并发上限 500** | [DeepSeek API Docs](https://api-docs.deepseek.com/)、[Models & Pricing](https://api-docs.deepseek.com/quick_start/pricing/) |
| DeepSeek V4-Flash | 1M（官方默认） | $0.14（缓存命中 $0.0028） | $0.28 | 284B 总参/13B 激活；简单 Agent 任务上与 Pro 相当；速度快；**并发上限 2500**；最大输出 384K | [DeepSeek Models & Pricing](https://api-docs.deepseek.com/quick_start/pricing/) |
| Kimi K3 | 1,048,576（1M） | ¥20（缓存命中 ¥2，省 90%） | ¥100 | 始终推理；reasoning_effort(low/high/max)；工具调用/JSON/结构化输出 | [Kimi K3 定价](https://www.kimi.com/zh-cn/resources/kimi-k3-pricing) |
| Kimi K2.7-Code（高速版） | — | — | — | 输出约 180 tokens/s（短上下文 260） | [platform.kimi.com 文档](https://platform.kimi.com/docs/pricing/chat) |
| 通义 qwen3.8-max | 1M（≤1M 单价段） | 12 元 | 36 元 | Batch 半价、上下文缓存折扣、免费 100 万 token（90 天） | [阿里云百炼定价](https://help.aliyun.com/zh/model-studio/model-pricing) |
| 通义 qwen3-max | 258K 输入 | 2.5 元（≤32K）～7 元（128K-256K） | 10～28 元 | 阶梯计价 | 同上 |
| 通义 qwen-plus / qwen-flash | 1M | qwen3.7-plus 2 元（≤256K）/ qwen3.7-flash 0.2 元（≤32K） | qwen3.7-plus 8 元 / qwen3.7-flash 0.8 元 | qwen-long 达 10M | [阿里云模型信息](https://help.aliyun.com/zh/model-studio/model-qwen3-max)、[千问 AI 平台定价](https://platform.qianwenai.com/docs/developer-guides/getting-started/pricing) |
| Claude Opus 5 | 1M（默认） | $5 | $25 | 128K 输出；effort 参数；fast mode（提速至 2.5x，溢价）；限流 1000RPM/2M ITPM/400K OTPM | [Claude Pricing](https://platform.claude.com/docs/en/about-claude/pricing)、[Rate limits](https://platform.claude.com/docs/en/api/rate-limits) |
| Claude Sonnet 5 | 1M | $2（intro 至 2026-08-31，后 $3） | $10（后 $15） | 速度/质量平衡；限流同 Opus 5（1000RPM/2M ITPM/400K OTPM） | [Claude Pricing](https://platform.claude.com/docs/en/about-claude/pricing)、[Rate limits](https://platform.claude.com/docs/en/api/rate-limits) |
| Claude Haiku 4.5 | — | $1 | $5 | 轻量快速；限流同 Opus 5（1000RPM/2M ITPM/400K OTPM） | 同上 |
| GPT-5.6 Sol | 1.05M | $5（缓存 $0.50） | $30 | 旗舰推理/编程 | [OpenAI Pricing](https://openai.com/api/pricing/)、[Compare models](https://developers.openai.com/api/docs/models/compare) |
| GPT-5.6 Terra | 1.05M | $2（缓存 $0.20） | $12 | 智能/成本平衡 | 同上 |
| GPT-5.6 Luna | 1.05M | $0.20（缓存 $0.02） | $1.20 | 成本敏感高吞吐 | 同上 |

> ⚠️ **DeepSeek 官方涨价预警（2026-08 检索时点）**：DeepSeek 官方文档明确声明「计划在近期大幅上调 DeepSeek API 服务整体价格，具体方案以官方通知为准」（来源：[DeepSeek Models & Pricing](https://api-docs.deepseek.com/quick_start/pricing/)）。**本项目预算规划必须预留涨价空间，并将 DeepSeek 作为主力模型之一的方案做降级预案（Kimi/通义/GPT-Luna 兜底）。**

### 4.2 分题型选型建议（结合官方能力定位）

| 用途 | 推荐模型 | 依据（官方） |
|---|---|---|
| Misc / Web 简单题、批量扫描、信息收集 | DeepSeek V4-Flash、GPT-5.6 Luna、Claude Haiku 4.5、通义 qwen-flash | 轻量快速、成本低（[DeepSeek V4 公告](https://api-docs.deepseek.com/news/news260424)、[OpenAI Compare](https://developers.openai.com/api/docs/models/compare)） |
| Crypto 计算型/中间推理 | Kimi K2.7-Code 高速版（180-260 tok/s）、GPT-5.6 Terra | 官方标注高速输出（[platform.kimi.com](https://platform.kimi.com/docs/pricing/chat)） |
| Pwn / 逆向 / 复杂密码题 | Claude Opus 5（effort xhigh）、GPT-5.6 Sol、DeepSeek V4-Pro（thinking+high） | 官方定位「complex reasoning / deep reasoning / agentic」（[Claude choosing-a-model](https://platform.claude.com/docs/en/about-claude/models/choosing-a-model)、[OpenAI Models](https://developers.openai.com/api/docs/models)） |
| 长程多步 Agent 编排 | Claude Opus 5 / Fable 5（1M 上下文 + 长期 agent） | 官方「long-running agents」定位（[Claude choosing-a-model](https://platform.claude.com/docs/en/about-claude/models/choosing-a-model)） |

> 注：具体解题成功率数据可参考 Cybench 官方 leaderboard（Claude Mythos Preview 当前居首，[cybench.github.io](https://cybench.github.io/index.html)）；但赛事中实际模型能力需结合自建评测集验证。

### 4.3 API 超时、限流、报错的官方应对依据

| 风险 | 官方机制 | 应对策略（官方文档支撑） |
|---|---|---|
| 限流（RPM/TPM） | **OpenAI**：按 usage tier 分级（Tier1 500RPM/500K TPM → Tier5 15000RPM/40M TPM，消费越高自动升级；usage limit Free $100/月 → Tier5 $200K/月）；**Claude**：按 Start/Build/Scale tier 设限流 + 月度 spend cap（Start $500、Build $1,000、Scale $200,000/月）；各模型 1000 RPM / 2M ITPM / 400K OTPM（Fable 5 为 500K ITPM/100K OTPM）；**DeepSeek**：flash 并发上限 2500、pro 500 | 提前充值提升 tier；令牌桶削峰；多家 Provider 网关切换；Batch API（OpenAI 50% 折扣，异步）跑非实时任务；Claude 仅未缓存输入 token 计入 ITPM（实际可用额度更高）；429 响应带 `retry-after` 头可做退避（[OpenAI Rate limits](https://developers.openai.com/api/docs/guides/rate-limits)、[Claude Rate limits](https://platform.claude.com/docs/en/api/rate-limits)、[DeepSeek Pricing](https://api-docs.deepseek.com/quick_start/pricing/)） |
| 成本 | 各家都支持上下文缓存（Claude prompt caching、Kimi 缓存命中 ¥2/M 降 90%、阿里云缓存折扣、DeepSeek 缓存命中仅 $0.0028-0.003625/M） | System prompt/工具描述/知识库前缀做缓存友好设计，命中缓存可省 90%+ 输入成本（[Claude Pricing](https://platform.claude.com/docs/en/about-claude/pricing)、[Kimi K3](https://www.kimi.com/zh-cn/resources/kimi-k3-pricing)、[DeepSeek Pricing](https://api-docs.deepseek.com/quick_start/pricing/)） |
| 超时/报错 | OpenAI 官方建议固定模型快照保证行为一致；Claude 提供 fast mode 提速；DeepSeek 官方文档声明**近期将大幅涨价** | 多 Provider 故障切换：同一任务分发到多家的同等级模型竞速，谁先回谁赢（参考 CTF-Agent 多模型竞速架构）；超时指数退避重试；**DeepSeek 涨价预警→预算预留 + Kimi/通义/GPT-Luna 降级预案**（[OpenAI Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering)、[DeepSeek Pricing](https://api-docs.deepseek.com/quick_start/pricing/)） |
| 并发额度 | OpenAI 并发数受 tier 限制；Claude 按 tier；DeepSeek 官方公开并发上限（flash 2500 / pro 500） | 用 LiteLLM 统一网关聚合多家额度（官方文档收录于各家用例）；请求排队 + 令牌桶削峰；asyncio 信号量控制在官方并发上限内 |

### 4.4 多接口自动切换策略（推荐架构）

1. **统一网关层（LiteLLM / 自研）**：所有题型 Agent 只面向一个 OpenAI 兼容接口，网关背后挂 DeepSeek / Kimi / 通义 / OpenAI / Claude 多家（OpenAI 兼容格式是各家的共同基线：DeepSeek、Kimi 均官方支持 OpenAI 格式）。
2. **健康探针 + 熔断**：网关持续统计每家延迟/错误率，连续 N 次失败即降级到备用 Provider；预算超限自动切换低价模型。
3. **竞速策略**：关键题（Pwn/Rev）同时发给 Opus 5 与 GPT-5.6 Sol 与 V4-Pro，首个返回可靠结果者胜（对齐 verialabs/ctf-agent 的多模型 racing，[README](https://github.com/verialabs/ctf-agent)）。

---

## 五、推荐整套 AI-Agent 分层架构详细说明

> 设计目标：多道 CTF 题目同时并发运行、速度碾压、现场可演示。架构依据来源均为官方文档/成熟开源方案。

### 5.1 六层架构总览

```
┌─────────────────────────────────────────────────────┐
│ L6 可视化监控层（Grafana Live WebSocket / 自研面板） │
├─────────────────────────────────────────────────────┤
│ L5 校验纠错层（flag gate / 错误回溯 / 知识沉淀）     │
├─────────────────────────────────────────────────────┤
│ L4 Docker 沙盒执行层（隔离执行 EXP，防环境冲突）     │
├─────────────────────────────────────────────────────┤
│ L3 工具调度层（题型工具链 / MCP / 端口与资源调度）   │
├─────────────────────────────────────────────────────┤
│ L2 题型子 Agent 层（Web/Crypto/Rev/Pwn/Misc 专家）   │
├─────────────────────────────────────────────────────┤
│ L1 顶层调度层（并发协程调度 / 优先级队列 / 竞速）    │
└─────────────────────────────────────────────────────┘
```

### 5.2 各层职责与官方依据

**L1 顶层调度层**
- 职责：拉取题目列表 → 题型分类 → 分配子 Agent → 并发调度 → 汇总提交；任务优先级队列（简单题/高价值题优先）；毫秒级测速埋点。
- 并发依据：Python `asyncio` 官方库（「run Python coroutines concurrently」「distribute tasks via queues」）（[Python 官方文档](https://docs.python.org/3/library/asyncio.html)）；FastAPI `async def` + `BackgroundTasks` 支持异步高并发（[FastAPI 官方](https://fastapi.tiangolo.com/async/)）。
- 多智能体编排依据：LangChain 官方多智能体模式（subagents / handoffs / skills / router / custom workflow），其中 subagents 模式并行化 5 星（[LangChain 官方文档](https://docs.langchain.com/oss/python/langchain/multi-agent)）；LangGraph 是低层状态编排框架（[GitHub](https://www.github.com/langchain-ai/langgraph)）。

**L2 题型子 Agent 层**
- 职责：Web / Crypto / Reverse / Pwn / Misc 五类专属 Agent，每类配专属提示词模板 + 工具白名单 + Few-shot 示例（依据：OpenAI 官方 few-shot 指引——在 developer message 中提供多样化输入/输出示例「pick up the pattern」（[OpenAI Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering)））。
- 参考竞品：D-CIPHER 的 planner+executor 分工（[arXiv 2502.10931](https://arxiv.org/html/2502.10931)）；CHYing 的「顾问-主攻手」双 Agent（[腾讯云开发者社区](https://developer.cloud.tencent.com/article/2650350)）。

**L3 工具调度层**
- 职责：统一工具注册表（shell/python/network/jwt/file_analyzer/隐写/取证/逆向工具等）；MCP 适配（IDA、Volatility 等，参考 AUTOCTF 的 MCP 集成，[GitHub](https://github.com/eternaldooly/AUTOCTF)）；多任务端口/资源冲突解决。
- 多任务环境冲突解法：每题一个独立 Docker 网络 + 容器（参考 llm-ctf-agent 的「每题独立 Docker 网络」设计，[GitHub](https://github.com/greyhatgt/llm-ctf-agent-boilerplate)）；工具白名单按题型裁剪，避免「用 C/C++ 逆向工具处理 Python 代码」式误用（NYU-CTF-Bench 论文自述问题，[arXiv](https://arxiv.org/html/2406.05590)）。

**L4 Docker 沙盒执行层**
- 职责：隔离执行 EXP、防逃逸、防环境污染；失败自动回收。
- 依据：Docker 官方 AI Sandboxes 文档——microVM 隔离、独立内核/网络/Docker Engine、凭证由 host 代理注入、deny-by-default 网络策略（[Docker 官方文档](https://docs.docker.com/ai/sandboxes/security/)）；如需更强隔离用 gVisor（runsc runtime，用户态拦截系统调用，防容器逃逸）（[gVisor 官方](https://gvisor.dev/docs/user_guide/production/)）。

**L5 校验纠错层**
- 职责：flag 提交前校验（格式/来源溯源/铁证检测，参考 hydra 的 `flag_gate.py` pre-commit gate，[GitHub](https://github.com/iamkorun/hydra)）；失败日志回传模型自我修正（ReAct reflection，OpenAI 官方 prompt 指南建议自评/反思，[OpenAI Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering)）；僵局检测与熔断（参考 LLM-CTF-Solver 的六维僵局检测，[GitHub](https://github.com/gehewu/LLM-CTF-Solver)）；解题知识沉淀（ChromaDB/RAG）。

**L6 可视化监控层**
- 职责：实时展示每题状态/耗时/花费/日志；现场演示大屏。
- 依据：Grafana 官方提供 HTTP API（数据源查询 `POST /api/ds/query`）与 **Grafana Live**（WebSocket Pub/Sub 实时推送数据到面板，可免除轮询）（[Grafana 官方文档](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/)）。

### 5.3 并发调度与资源冲突方案（重点）

| 冲突场景 | 解决方案 | 依据 |
|---|---|---|
| 多题抢占端口 | 每容器独立网络 + 动态端口映射；平台控制面 API 已分配 entrypoints 的按其指引连接 | [llm-ctf-agent Docker 网络设计](https://github.com/greyhatgt/llm-ctf-agent-boilerplate) |
| 工具冲突（版本/依赖） | 每题独立镜像/容器，工具按题型白名单裁剪 | [NYU 论文工具误用问题](https://arxiv.org/html/2406.05590) |
| 环境冲突（文件/内存） | Docker 资源限制（memory/cpu 限额）+ watchdog 内存超限杀容器（90% 阈值，参考 hydra） | [hydra watchdog](https://github.com/iamkorun/hydra)、[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/security/) |
| 并发上限 | asyncio 信号量控制最大并发任务数；API 令牌桶削峰 | [Python asyncio 官方](https://docs.python.org/3/library/asyncio.html) |
| 死循环烧钱 | watchdog（重复 bash 命令、成本上限、空闲超时）→ 强杀 + 记录原因 | [hydra watchdog](https://github.com/iamkorun/hydra) |

### 5.4 毫秒级测速埋点方案

- 在调度层为「取题 → 分类 → 派发 → 首次 LLM 响应 → 首次工具执行 → flag 提交」各环节打点（Python `time.perf_counter_ns()`），日志入时序库（Prometheus/InfluxDB 行协议经 Grafana `/api/live/push/:streamId` 推送，[Grafana Live 官方](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/)）。

---

## 六、我的项目专属 3~5 项差异化核心创新点

> 创新点全部针对竞品短板提炼（详见 2.3），每一项都有可验证的落地指标。

### 创新点 1：多题并发 + 每题多模型竞速引擎（速度碾压）
- 针对短板：SageCTF 平均每题 5 小时（[官方博客](https://www.opensage-agent.ai/blog/sagectf.html)）、多数竞品串行。
- 方案：asyncio 协程池 + 信号量限流，全部题目并行推进；每道难题同时交给 2-3 家顶级模型竞速（参考 verialabs/ctf-agent 的 solver swarm，[README](https://github.com/verialabs/ctf-agent)）。
- 验收指标：3 小时初赛内并发覆盖 100% 题目；单题平均首解时间 < 10 分钟。

### 创新点 2：分级模型路由 + 上下文缓存 + 预算熔断（成本碾压）
- 针对短板：竞品普遍未披露成本控制。
- 方案：题型/难度路由到轻量或重型模型；System Prompt 与工具描述做缓存友好前缀（Kimi 缓存命中省 90% 输入成本，[官方定价](https://www.kimi.com/zh-cn/resources/kimi-k3-pricing)；Claude prompt caching，[官方文档](https://platform.claude.com/docs/en/about-claude/pricing)）；cost-cap watchdog（参考 hydra `--watchdog-cost-cap`，[GitHub](https://github.com/iamkorun/hydra)）。
- 验收指标：单场初赛 API 预算可控在预设 X 元内。

### 创新点 3：确定性 watchdog + 六维僵局检测 + 失败日志回传纠错（稳定性碾压）
- 针对短板：D-CIPHER 论文自述 retries/loss of focus/hallucinations（[arXiv](https://arxiv.org/html/2502.10931)）；CHYing 曾因复杂架构死锁被迫重构（[腾讯云](https://developer.cloud.tencent.com/article/2650350)）。
- 方案：0-token 确定性 watchdog（重复命令/内存超限/空闲超时/成本超限自动杀容器，参考 [hydra](https://github.com/iamkorun/hydra)）；僵局检测后强制切换策略（换工具/换模型/换思路）；失败轨迹回填 prompt 让模型自省修正（ReAct reflection，[OpenAI 官方](https://developers.openai.com/api/docs/guides/prompt-engineering)）。
- 验收指标：单题死循环率 < 5%；错误尝试可自动回退重来。

### 创新点 4：五大题型专属 Agent + 专属工具链/Prompt（专业度碾压）
- 针对短板：Cyber-AutoAgent 官方失败分析——通用框架稀释专精能力（[Discussion #41](https://github.com/westonbrown/Cyber-AutoAgent/discussions/41)）；NYU 论文——模型工具误用（[arXiv](https://arxiv.org/html/2406.05590)）。
- 方案：Web / Crypto / Reverse / Pwn / Misc 五类专属子 Agent，每类独立 System Prompt + Few-shot 模板（OpenAI 官方 few-shot 指引，[文档](https://developers.openai.com/api/docs/guides/prompt-engineering)）+ 工具白名单 + 专属 EXP 模板库。
- 验收指标：五类题型在本地题库（NYU-CTF-Bench 200 题）上均有独立解出记录，无跨题型工具误用。

### 创新点 5：实时可视化指挥面板 + 现场演示大屏（答辩碾压）
- 针对短板：绝大多数竞品无可视化；决赛要求现场系统演示（官方：[gm7.org](https://www.gm7.org/archives/131915)）。
- 方案：Grafana Live WebSocket 实时推送每题状态/耗时/花费/思维轨迹（[Grafana 官方](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/)）；演示模式一键暂停/人工接管（呼应官方「支持人机持续交互」赛制）。
- 验收指标：面板 < 1s 刷新延迟；决赛答辩演示脚本 10 分钟讲清架构与数据。

---

## 七、完整技术栈清单

### 7.1 语言与运行时
- Python 3.12+（Agent 主逻辑、asyncio 并发）— [asyncio 官方](https://docs.python.org/3/library/asyncio.html)
- Node.js/TypeScript（可选，可视化面板前端）
- Docker / Docker Compose（沙盒与题环境）— [Docker 官方](https://docs.docker.com/ai/sandboxes/)

### 7.2 编排与调度
- FastAPI + Uvicorn（API 服务层、异步并发）— [FastAPI 官方](https://fastapi.tiangolo.com/async/)
- LangGraph / LangChain（多智能体状态编排；subagents/router 模式）— [LangChain 官方](https://docs.langchain.com/oss/python/langchain/multi-agent)
- asyncio 信号量 + 优先级队列（asyncio.Queue）— [Python 官方](https://docs.python.org/3/library/asyncio.html)
- 可选 Celery/RQ（若需跨进程分布式批量）

### 7.3 模型接入与网关
- LiteLLM 统一网关（聚合 DeepSeek/Kimi/通义/OpenAI/Claude，OpenAI 兼容格式为共同基线）
- OpenAI SDK / Anthropic SDK 原生直连（竞速时双通道）

### 7.4 沙盒与安全执行
- Docker（每容器独立网络、资源限额）
- gVisor（runsc runtime，防逃逸增强）— [gVisor 官方](https://gvisor.dev/docs/user_guide/production/)
- watchdog 边车进程（重复命令/内存/成本/空闲监控）— 参考 [hydra](https://github.com/iamkorun/hydra)

### 7.5 工具链（按题型白名单）
- Web：Burp Suite CLI/API、sqlmap、curl、requests
- Crypto：pycryptodome、RsaCtfTool、CyberChef、factordb
- Reverse：Ghidra headless、radare2/rizin、JADX、uncompyle6、wabt
- Pwn：pwntools、checksec、ropper、gdb+peda/pwndbg、ROPgadget
- Misc：binwalk、Stegsolve、Wireshark/tshark、Volatility、foremost、strings
- 通用：file/strings/xxd/zipinfo/pngcheck

### 7.6 知识库与记忆
- ChromaDB / FAISS（RAG 知识库，沉淀解题模板）— 参考 [LLM-CTF-Solver](https://github.com/gehewu/LLM-CTF-Solver)、[CoRedteam-CTF](https://github.com/CorruptingHeart-Y/CoRedteam-CTF)

### 7.7 可观测与可视化
- Grafana + Grafana Live（WebSocket 实时面板）— [Grafana 官方](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/)
- Prometheus / InfluxDB（指标时序存储）
- Python logging + structlog（结构化日志、测速埋点）

### 7.8 平台交互
- 大赛平台控制面 API 客户端（openapi.json 自动发现；Agent-Token 认证；start/submit/stop 生命周期）— 参考 [aiagentsec-benchmarks agent-operator.md](https://github.com/o0x1024/aiagentsec-benchmarks/blob/main/docs/agent-operator.md)（非官方，仅参考）

---

## 八、全部已知坑点、风险以及规避方案

| # | 风险 | 现象 | 预处理方案 | 依据 |
|---|---|---|---|---|
| 1 | API 限流（RPM/TPM） | 429 报错、请求被拒 | 预充值提升 tier；令牌桶削峰；多家 Provider 网关切换；Batch API 处理非实时任务 | [OpenAI Rate limits](https://developers.openai.com/api/docs/guides/rate-limits)、[Claude Pricing](https://platform.claude.com/docs/en/about-claude/pricing) |
| 2 | 网络超时 | 请求挂起、LLM 无响应 | 统一超时参数 + 指数退避重试 + 竞速双通道（另一家模型顶上） | [OpenAI Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering) |
| 3 | 并发冲突（端口/文件/工具） | 多题互相干扰、EXP 崩溃 | 每题独立 Docker 网络与容器；资源限额（memory/cpu）；工具按题型白名单 | [llm-ctf-agent](https://github.com/greyhatgt/llm-ctf-agent-boilerplate)、[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/security/) |
| 4 | 模型幻觉 | 编造 flag/EXP 不生效/方向跑偏 | 沙盒运行校验（跑了才算数）；flag gate 预检（格式/来源/铁证）；失败日志回填自纠；Few-shot 示例锚定 | [OpenAI Prompt engineering](https://developers.openai.com/api/docs/guides/prompt-engineering)、[hydra flag_gate](https://github.com/iamkorun/hydra) |
| 5 | EXP 运行崩溃 | 段错误/依赖缺失/内存爆 | Docker 内预装全部工具链；watchdog 内存 90% 阈值杀容器并回收；崩溃日志回传模型修正 | [hydra watchdog](https://github.com/iamkorun/hydra)、[gVisor](https://gvisor.dev/docs/user_guide/production/) |
| 6 | 评委环境缺少依赖 | 现场演示装不起来 | 演示机 Docker 化一键拉起（`docker compose up`）；离线依赖打包；预演清单核对 | [Docker 官方](https://docs.docker.com/ai/sandboxes/) |
| 7 | 演示翻车（断网/卡顿/面板黑屏） | 现场尴尬扣分 | Grafana Live 本地兜底模式（降级为静态页面刷新）；演示脚本 + 彩排 ≥3 次；备用演示机 | [Grafana 官方](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/) |
| 8 | 成本失控 | 预算烧光中途停机 | cost-cap watchdog 强杀；分级路由低价模型兜底；上下文缓存复用 | [hydra](https://github.com/iamkorun/hydra)、[Kimi 缓存定价](https://www.kimi.com/zh-cn/resources/kimi-k3-pricing) |
| 9 | 死循环/逻辑死锁 | Agent 反复重试同一动作 | 确定性 watchdog（bash 重复检测、空闲超时）；僵局检测后强制策略切换（换工具/模型/思路） | [hydra](https://github.com/iamkorun/hydra)、[LLM-CTF-Solver 六维僵局](https://github.com/gehewu/LLM-CTF-Solver) |
| 10 | flag 格式不确定 | 提交格式错误浪费次数 | 从题目描述提取 flag_format；多格式候选预提交校验；5 层 flag 检测（正则→分析→LLM→Pro→人工） | [LLM-CTF-Solver flag_detector](https://github.com/gehewu/LLM-CTF-Solver) |
| 11 | 平台 API 协议不明确 | 测试赛前无从适配 | 提前写好 openapi 自动发现客户端；测试赛首日全接口冒烟；保留人工 curl 兜底通道 | [agent-operator.md（参考）](https://github.com/o0x1024/aiagentsec-benchmarks/blob/main/docs/agent-operator.md) |
| 12 | 答辩论据不足 | 评委问不出「为什么快/稳」 | 测速埋点数据说话（每环节耗时图表）；竞品对比数据（本报告第二章）进答辩 PPT | 本报告 2.3/5.4 |

---

## 九、开发任务先后顺序

### 阶段 0：开发前置准备（8 月中上旬，报名截止 8-10 前完成报名）
1. 完成报名（官网 game.gcsis.cn，[gm7.org](https://www.gm7.org/archives/131915)）；领取阿里云 300 元算力券。
2. 申请/充值多家模型 API Key（DeepSeek、Kimi、通义、OpenAI、Claude），确认各 tier 限流。
3. 搭建本地题库：拉取 NYU-CTF-Bench（[GitHub](https://github.com/nyu-llm-ctf/nyu_ctf_bench)）+ 西湖论剑历年真题（3.1）+ 强网杯（3.2）+ picoCTF 精选（3.3）。
4. 编写平台 API 客户端骨架（openapi.json 自动发现 + Agent-Token 认证 + start/submit/stop）。

### 阶段 1：模块编码（测试赛 8-18/19 之前）
1. L1 调度层：asyncio 并发池 + 优先级队列 + 测速埋点。
2. L2 题型 Agent 层：先做 Web/Crypto（好解易验证），再做 Reverse/Pwn/Misc。
3. L3 工具层：工具注册表 + Docker 基础镜像（预装全套工具）。
4. L4 沙盒层：Docker 隔离 + watchdog 边车。
5. L5 校验纠错层：flag gate + 失败回传 + 知识库（ChromaDB）。
6. L6 可视化层：Grafana + 实时推送。

### 阶段 2：本地题库测速迭代（8-19 ～ 8-21 初赛前）
1. 用 NYU-CTF-Bench 200 题逐题跑分，记录每类解出率与耗时。
2. 针对低分题型迭代 Prompt / Few-shot / 工具链（OpenAI 官方 few-shot 方法，[文档](https://developers.openai.com/api/docs/guides/prompt-engineering)）。
3. 压测并发：同时 20 题并行，验证端口/内存/限流无冲突。
4. 固化「单题超时上限」「单题预算上限」「全局预算熔断」三档保护。

### 阶段 3：可视化面板制作（与阶段 2 并行）
1. 指标打点 → Prometheus/InfluxDB → Grafana 面板。
2. 演示模式：一键全屏大屏 + 暂停/人工接管。

### 阶段 4：赛前压力测试 + 答辩材料准备（8-19 ～ 8-21；决赛前 9 月）
1. 模拟 3 小时初赛全流程演练 ≥2 次；故障注入演练（断网、限流、模型 500）。
2. 答辩 PPT：架构图（第五章）+ 竞品对比（第二章）+ 测速数据 + 演示脚本。
3. 决赛清单：演示机 Docker 化、备用机、离线依赖、检查「现场演示 + 代码审查 + 技术问答」要求（[官方](https://www.gm7.org/archives/131915)）。

---

## 十、赛后技术沉淀、适配网络安全岗位的长期深耕路线

### 10.1 技术沉淀（把比赛资产转化为长期能力）
1. **开源化**：将平台 API 客户端、题型 Agent 框架、watchdog、flag gate 拆成独立开源项目（对标 hydra/LLM-CTF-Solver 的工程化水平）。
2. **数据集沉淀**：把西湖论剑/强网杯历年真题 + 自建题解整理成中文 CTF-Agent 评测集（对标 NYU-CTF-Bench 模式，[GitHub](https://github.com/nyu-llm-ctf/nyu_ctf_bench)）。
3. **论文化**：以「多题并发 CTF-Agent 的调度与校验」为课题，参考 D-CIPHER（[arXiv 2502.10931](https://arxiv.org/html/2502.10931)）/ SageCTF（[官方博客](https://www.opensage-agent.ai/blog/sagectf.html)）的写法输出论文。

### 10.2 适配网络安全岗位的深耕路线
1. **AI 安全工程师 / 安全智能体开发**：本项目的 Agent 编排、工具调用、沙盒、校验纠错能力直接对应安恒「安全智能体开发应用平台」技术栈（[安恒恒脑安全智能体平台](https://www.dbappsecurity.com.cn/content/details4756_33337.html)）。
2. **攻防研究（红队/渗透自动化）**：把题型 Agent 扩展到自动化渗透测试（对标 Cyber-AutoAgent 的 XBOW 84.62% 路线，[GitHub](https://github.com/westonbrown/Cyber-AutoAgent)）。
3. **大模型安全评测**：参与 Cybench/NYU-CTF-Bench 等开源基准共建（[cybench.github.io](https://cybench.github.io/index.html)），是 Anthropic/OpenAI/xAI 等官方 System Card 引用的权威基准。
4. **赛事荣誉转化**：决赛晋级即获安恒实习生优先录用 + 认证培训名额（官方奖励，[gm7.org](https://www.gm7.org/archives/131915)），直接衔接就业。

---

## 附录：关键来源索引

| 主题 | URL |
|---|---|
| 第九届西湖论剑报名启动（杭州网官方媒体） | https://hznews.hangzhou.com.cn/jingji/content/2026-07/14/content_9254726.htm |
| 第九届官方公告转载（完整赛程/奖励/算力） | https://www.gm7.org/archives/131915 |
| 西湖论剑×阿里云算力支持 | http://zhousa.com/archives/93695.html |
| 第八届决赛战报（安恒官网） | https://www.dbappsecurity.com.cn/content/details4756_30609.html |
| 第八届初赛官方 WriteUp（下） | https://cn-sec.com/archives/3670488.html |
| 第八届初赛官方 WriteUp（上） | https://www.ctfiot.com/225639.html |
| 西湖论剑 2025 Writeup | https://cn-sec.com/archives/3647997.html |
| CTF-Agent（BSidesSF 2026 冠军） | https://github.com/verialabs/ctf-agent |
| llm-ctf-agent boilerplate | https://github.com/greyhatgt/llm-ctf-agent-boilerplate |
| NYU-CTF-Bench | https://github.com/nyu-llm-ctf/nyu_ctf_bench ｜ https://nyu-llm-ctf.github.io/ ｜ https://arxiv.org/html/2406.05590 |
| D-CIPHER 论文 | https://arxiv.org/html/2502.10931 ｜ 代码 https://github.com/NYU-LLM-CTF/nyuctf_agents |
| InterCode-CTF | https://github.com/princeton-nlp/intercode ｜ https://intercode-benchmark.github.io/#ctf |
| SageCTF（OpenSage 官方博客） | https://www.opensage-agent.ai/blog/sagectf.html |
| CHYing-Agent 实战解析 | https://developer.cloud.tencent.com/article/2650350 |
| Cyber-AutoAgent | https://github.com/westonbrown/Cyber-AutoAgent ｜ 失败分析 https://github.com/westonbrown/Cyber-AutoAgent/discussions/41 |
| AUTOCTF | https://github.com/eternaldooly/AUTOCTF |
| hydra（补充竞品） | https://github.com/iamkorun/hydra |
| LLM-CTF-Solver（补充竞品） | https://github.com/gehewu/LLM-CTF-Solver |
| Cybench 基准 | https://cybench.github.io/index.html ｜ https://arxiv.org/abs/2408.08926 |
| DeepSeek API 官方文档 | https://api-docs.deepseek.com/ ｜ V4 公告 https://api-docs.deepseek.com/news/news260424 ｜ 定价 https://api-docs.deepseek.com/quick_start/pricing/ |
| Kimi K3 官方定价 | https://www.kimi.com/zh-cn/resources/kimi-k3-pricing ｜ https://platform.kimi.com/docs/pricing/chat |
| 阿里云百炼定价 | https://help.aliyun.com/zh/model-studio/model-pricing ｜ 千问 AI 平台定价 https://platform.qianwenai.com/docs/developer-guides/getting-started/pricing |
| Claude 官方定价 | https://platform.claude.com/docs/en/about-claude/pricing ｜ 限流 https://platform.claude.com/docs/en/api/rate-limits |
| OpenAI 官方定价/限流 | https://openai.com/api/pricing/ ｜ https://developers.openai.com/api/docs/guides/rate-limits |
| OpenAI Prompt engineering（幻觉/Few-shot/RAG） | https://developers.openai.com/api/docs/guides/prompt-engineering |
| Python asyncio 官方 | https://docs.python.org/3/library/asyncio.html |
| FastAPI 官方（并发/后台任务） | https://fastapi.tiangolo.com/async/ |
| LangChain 多智能体官方 | https://docs.langchain.com/oss/python/langchain/multi-agent |
| Docker AI Sandboxes 安全文档 | https://docs.docker.com/ai/sandboxes/security/ |
| gVisor 官方 | https://gvisor.dev/docs/user_guide/production/ |
| Grafana API / Live 官方 | https://grafana.com/docs/grafana/latest/developer-resources/api-reference/ |
| AI-Agent CTF 平台 API 交互参考（非官方） | https://github.com/o0x1024/aiagentsec-benchmarks/blob/main/docs/agent-operator.md |

> ⚠️ 本报告中标注「未查到官方说明」的事项（如西湖论剑官方 API 并发上限、答辩交付物模板、环境安全限制），将在测试赛（8-18/19）拿到真实平台文档后补充更新。

---
*报告完*
