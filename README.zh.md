# 西湖论剑 CTF-Agent (xihu-sword-ctf-agent)

> 🌏 **English documentation / 英文文档**: [README.md](./README.md)

> ⚠️ **诚实声明（务必先读）**：本项目在真实赛事平台上的最终成绩为 **0 个有效提交 flag**。仓库中所有"解出 / 通过率"数据，均指对历年真题（`data/questions_real/` 题库）的**离线确定性分析**，不代表任何线上赛事得分。本项目**不宣称具备 LLM 自主推理能力**——真实能力是一个**确定性静态分析器（presolve）**的题型覆盖度。详见下方[诚实 KPI](#诚实-kpi)。

一个开源的 **CTF（夺旗赛）AI Agent 解题框架**。Agent 自动轮询 DASCTF 类赛事平台、对题目分类、先跑确定性解题器，只在静态分析无法命中时才升级给 LLM。基于「西湖论剑」AI CTF 赛道实战打磨。

---

> ℹ️ **路径约定**：本 README 中，行内代码里的路径相对 `ctf_agent/`；markdown 链接相对本文件。

## 为什么要做这个

多数"CTF Agent"本质就是"套了 shell 的 LLM"。这个项目反其道而行：**确定性优先**。预处理层（`core/presolve.py`）并行扇出数十个即用型 skill（RSA 攻击、隐写提取、源码审计、多层 base64 解码……），LLM 只是最后兜底，且被白名单、token 预算、墙钟止损三层约束。最终得到一个**可复现、可调试、对自身能力坦诚**的系统。

## 架构概览

```
ctf_agent/
├── core/          主循环、presolve 静态分析器、监督 Agent、墙钟止损
├── agents/        各题型求解器（crypto_toolkit / misc / web / reverse / pwn …）
├── skills/        56 个确定性解题 skill（run(params) -> dict 接口；机器计数见 `scripts/_kpi_canonical.py`）
├── llm/           LLM 客户端（provider 白名单、fail-closed 熔断）
├── ctfplatform/   赛事平台客户端（DASCTF 类）、重试 / fail-open 提交路径
├── sandbox/       代码执行沙箱（subprocess 隔离）
├── eval/          真题集 benchmark（诚实 KPI 度量）
├── data/questions_real/   历年真题题库结构（多数 flag 存 SHA-256；少量久远公开赛事如安洵杯 2020 保留明文；2026 西湖论剑赛事题已排除）
├── config.py      配置（默认值 + 环境变量回退）
├── run.py         入口（--mode cli/web/mock）
└── setup.sh       环境初始化
```

### 解题链路

```
平台轮询 → 分类 → 附件下载 + 靶机探测
        → 确定性 skill(56) ⇄ LLM 推理(白名单 provider)
        → flag 校验 → 平台提交(fail-closed)
```

- **监督架构**：`core/main_agent.py` 按题规划，`core/supervisor_agent.py` 强制步骤预算、工具优先纪律，并区分"请求失败"与"flag 错误"（提交断路器 bug 的事后修复）。
- **确定性优先**：`skills/` 含 56 个即用 skill（机器计数见 `scripts/_kpi_canonical.py`），`core/presolve.py` 在任何 LLM token 消耗前先跑完它们。
- **仅白名单 LLM**（赛事规则 §3）；多源回退含 401/402 熔断、按题 token 预算、重型模型升级策略。
- **作战脚本**：`scripts/_race_start.py --compete` = 首血扫描 → 稳定轮询 → 终报，内置强制 e2e 数据链路预检（fail-closed）。

## 硬性门禁（经验固化）

| 门禁 | 内容 | 执行方 |
|------|------|--------|
| 测试门禁 | 真实 `pytest` 运行，禁止逐文件假循环 | `setup.sh`（失败即 exit 1） |
| E2E 门禁 | 平台确实提供题目数据 | `scripts/_e2e_verify.py`，接入 `--compete` |
| 网络门禁 | 代理存活 / LLM 端点可达 | `scripts/_net_check.py`（`trust_env=False`） |
| 密钥门禁 | 暂存文件不含明文密钥 | pre-commit 钩子（`scripts/_scan_secrets.py`） |
| 写租约门禁 | 单 scope 单写者；越界提交被拒 | `scripts/_lease.py` + pre-commit |

## 快速开始

```bash
cd ctf_agent
bash setup.sh                      # 装依赖 + 预检 + 跑测试
export CTF_AGENT_LLM_PROVIDER=deepseek
export CTF_AGENT_LIGHT_MODEL=deepseek-chat
export DEEPSEEK_API_KEY=sk-xxx     # 你的密钥，勿提交
.venv/Scripts/python.exe run.py --mode mock --category crypto   # 离线冒烟
.venv/Scripts/python.exe run.py --mode cli                      # 本地刷题
```

配置全部走环境变量（见 `config.py`）：`DASCTF_TOKEN`、`DASCTF_BASE_URL`、各 provider API Key。**密钥绝不入库**——钩子会拒绝。

## 诚实 KPI

对 `data/questions_real/`（共 92 道历年真题），跑**真实**工具链路：

| 指标 | 结果 |
|------|------|
| **offline_verified**（严格真题 KPI，机器棘轮只升不降） | **14** |
| 确定性管线（presolve 直出） | **14 / 92**（全集，15.2%） |
| LLM 自主推理贡献 | **0 / 14**（严格 KPI 集内无一题由 LLM 自主推理解出） |
| 回归集可复现计数 | **16 / 16**（13 题严格 KPI 集 + 10732/10735 治理修复 + specialcurve2，攻击链可机器复现；REGRESSION_CHECKS 16 道全过） |
| **held-out 推理池**（未见过的非平凡题） | **2 题** —— 与上述 14 道 KPI 题**不相交**（清洗后：排除 7 道 WRITEUP 重建题 + 1 道源码泄露 web 题；原「10 题」含这些） |
| held-out 池上的 LLM 自主推理（2026-09-22 实测，干净池） | 池内 **2 / 2** 解出 —— **LLM 自主推理 1 / 2**（`real_crypto_dnui_keyboard`），**确定性 presolve 1 / 2**（`real_reverse_js`）；sha256 真值闭环 |

> 我们从不把 14 除以 2 —— 两集合不相交，`14/2` 是欺骗性比率，故工具恒输出 `coverage_of_heldout=None` 而非一个数字。held-out 口径测的是**另一件事**——未见题上的真实自主 LLM 推理，不是 14 的几成。在干净 2 题池（2026-09-22 实测，deepseek + E3 证据注入，sha256 闭环，报告 `ctf_agent/heldout_evidence/benchmark_report_clean2_20260922_deepseek.json`）上 **LLM 自主推理 = 1 / 2**（`real_crypto_dnui_keyboard`；另一题 `real_reverse_js` 由确定性 presolve 解出）。旧「LLM 0 / 10」是**两个已修复 bug 的产物**：(1) `bug2`——验证器把正确 flag 拿去和退役混合集答案表比对，误判为幻觉（真解被记成失败）；(2) held-out 分母被 7 道 WRITEUP 重建题（flag 明文在附件）+ 1 道源码泄露 web 题（`real_web_gongye_web2`，flag 在提供的 `index.php` 里）污染。排掉污染后，干净未见池上的真实 LLM 自主推理率 = **1 / 2**（样本极小，扩池是待办）。

即：**能力 = 静态分析器覆盖度**，不是 LLM 推理。要解更多题型，就写更多确定性 skill。我们直言此事，因为对开源安全工具而言，夸大能力是最容易翻车的方式。

## 安全与合规

本仓库仅发布**工程骨架与方法论**。红线：

1. **flag 按赛事如实处理**：绝大多数历史真题 flag 以 SHA-256 存储；少量来自早已公开的赛事（如安洵杯 2020，其 writeup 已全网公开）保留明文。本项目**不包含 2026 西湖论剑赛事自身的 flag 与附件**（经 `.gitignore` 排除）。严格 KPI 的判分真值（`flag_sha256`）**并未隐藏**：它随 `data/questions_real/**` 的题面 JSON 一并入库（在 `ctf_agent/.gitignore` 中以 `!data/questions_real/**` 反忽略）；仅原始明文 `flag.txt` / `flag.png` / `*_attachments/` 被 `.gitignore` 排除。
2. **密钥不入库**：LLM Key 与平台 Token 仅经环境变量 / 注册表注入。
3. **内部赛事资源不公开**（`data/race_details/`、附件、签名）经 `.gitignore` 排除。
4. **诚实水位**：不夸大能力，详见上文。

## 项目状态

我们发布这个仓库时，把它的数字如实写出来，包括不好看的那些。严格 KPI 是 **92 道已收集真题中 14 道带完整证据解出**（约 **15.2%**），"解出"的定义是确定性、可重跑的求解器产出 flag 且与题面 SHA-256 匹配 —— 其中 LLM 贡献 **0/14**。在 **held-out 池**（10 道未见过的非平凡题，与那 14 道不相交）上，LLM 在真实运行中解出 **0/10**（566,570 tokens）；池内唯一一解来自确定性预扫层，不是模型。把预算翻倍到 696,506 tokens 后，"预算耗尽"这一类失败被彻底消除，但**多解出 0 道** —— 瓶颈是模型能力，不是投入。`14/10` 从不计算。以上全部有本仓库内的产物支撑，你可以自己重跑。

## License

[MIT](LICENSE) — 开源用于学习与研究，请遵守各 CTF 赛事规则与平台条款。
