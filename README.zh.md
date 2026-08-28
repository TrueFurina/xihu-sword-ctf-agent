# 西湖论剑 CTF-Agent (xihu-sword-ctf-agent)

> 🌏 **English documentation / 英文文档**: [README.md](./README.md)

> ⚠️ **诚实声明（务必先读）**：本项目在真实赛事平台上的最终成绩为 **0 个有效提交 flag**。仓库中所有"解出 / 通过率"数据，均指对历年真题（`data/questions_real/` 题库）的**离线确定性分析**，不代表任何线上赛事得分。本项目**不宣称具备 LLM 自主推理能力**——真实能力是一个**确定性静态分析器（presolve）**的题型覆盖度。详见下方[诚实 KPI](#诚实-kpi)。

一个开源的 **CTF（夺旗赛）AI Agent 解题框架**。Agent 自动轮询 DASCTF 类赛事平台、对题目分类、先跑确定性解题器，只在静态分析无法命中时才升级给 LLM。基于「西湖论剑」AI CTF 赛道实战打磨。

---

## 为什么要做这个

多数"CTF Agent"本质就是"套了 shell 的 LLM"。这个项目反其道而行：**确定性优先**。预处理层（`core/presolve.py`）并行扇出数十个即用型 skill（RSA 攻击、隐写提取、源码审计、多层 base64 解码……），LLM 只是最后兜底，且被白名单、token 预算、墙钟止损三层约束。最终得到一个**可复现、可调试、对自身能力坦诚**的系统。

## 架构概览

```
ctf_agent/
├── core/          主循环、presolve 静态分析器、监督 Agent、墙钟止损
├── agents/        各题型求解器（crypto_toolkit / misc / web / reverse / pwn …）
├── skills/        49 个确定性解题 skill（run(params) -> dict 接口）
├── llm/           LLM 客户端（provider 白名单、fail-closed 熔断）
├── ctfplatform/   赛事平台客户端（DASCTF 类）、重试 / fail-open 提交路径
├── sandbox/       代码执行沙箱（subprocess 隔离）
├── eval/          真题集 benchmark（诚实 KPI 度量）
├── data/questions_real/   历年真题题库结构（真值已占位脱敏）
├── config.py      配置（默认值 + 环境变量回退）
├── run.py         入口（--mode cli/web/mock）
└── setup.sh       环境初始化
```

### 解题链路

```
平台轮询 → 分类 → 附件下载 + 靶机探测
        → 确定性 skill(49) ⇄ LLM 推理(白名单 provider)
        → flag 校验 → 平台提交(fail-closed)
```

- **监督架构**：`core/main_agent.py` 按题规划，`core/supervisor_agent.py` 强制步骤预算、工具优先纪律，并区分"请求失败"与"flag 错误"（提交断路器 bug 的事后修复）。
- **确定性优先**：`skills/` 含 49 个即用 skill，`core/presolve.py` 在任何 LLM token 消耗前先跑完它们。
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

对 `data/questions_real/` 15 道历年真题，跑**真实**工具链路：

| 指标 | 结果 |
|------|------|
| 确定性管线（presolve 直出） | **14 / 15（93.3%）** |
| LLM 自主推理贡献 | **0 / 1**（唯一未解题为数据集缺陷，非能力缺口） |

即：**能力 = 静态分析器覆盖度**，不是 LLM 推理。要解更多题型，就写更多确定性 skill。我们直言此事，因为对开源安全工具而言，夸大能力是最容易翻车的方式。

## 安全与合规

本仓库仅发布**工程骨架与方法论**。红线：

1. **真 flag 永不公开**：所有明文 flag 已剥离，仅留 `<REDACTED>` / sha256 占位；真值文件在 `.gitignore` 中屏蔽。
2. **密钥不入库**：LLM Key 与平台 Token 仅经环境变量 / 注册表注入。
3. **内部赛事资源不公开**（`data/race_details/`、附件、签名）经 `.gitignore` 排除。
4. **诚实水位**：不夸大能力，详见上文。

## License

[MIT](LICENSE) — 开源用于学习与研究，请遵守各 CTF 赛事规则与平台条款。
