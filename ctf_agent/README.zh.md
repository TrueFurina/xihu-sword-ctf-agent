# 西湖论剑 CTF-Agent

> 英文版：[README.md](./README.md)

> ⚠️ **竞赛真实战绩声明**：本项目初赛真实平台 accepted = **0 解出、0 有效提交**。本文描述框架的*工程能力与治理机制*，**不代表任何竞赛解题战绩**。凡「解出 / 水位」类表述若无「平台 accepted」记录，均指本地离线分析或沙盒实测，非竞赛战绩。统一口径见 `../deliverables/协同协议/真实战绩口径声明.md`。

> 🏷️ **历史分层（2026-08-24）**：`git log` 是**考古层**——含过程噪音（草稿提交、回滚、并发会话搅动）。**事实层** = tag `verified-2026-08-24` + [`REAL_SOLVES_LEDGER.md`](./REAL_SOLVES_LEDGER.md)。引用事实以台账/tag 为准，不以裸 git 历史为准。

面向 **西湖论剑** CTF 竞赛的 AI 自动解题 Agent：轮询 DASCTF 平台 → 分诊分类 →
下载附件/探测靶机 → 确定性 skill 与 LLM 推理协同 → flag 校验 → 平台提交。
面向西湖论剑竞赛构建并演练（初赛真实平台 accepted = 0，含赛后深度复盘与治理机制沉淀）。

**私有竞赛仓库**——含内部复盘、赛题数据与治理工具，请勿外传。

## 做什么

```
平台轮询 → 分诊/分类 → 附件下载 + 靶机探测
        → 确定性 skill（49 个）⇄ LLM 推理（官方白名单 provider）
        → flag 校验 → 平台提交（请求故障 fail-closed，不吞正确 flag）
```

- **监督架构**：`core/main_agent.py` 规划，`core/supervisor_agent.py` 执行
  步数预算、工具优先纪律、请求故障与 flag 错误分离（提交熔断 bug 的赛后修复）。
- **确定性优先**：`skills/` 49 个即插即用 skill（RSA 高位指数、PKCS#1 填充预言、
  base64 多层、大文件分析、CMS 源码审计、Go/APK 工具链……），统一预扫层
  `core/presolve.py` 在 LLM 烧 token 之前先跑。
- **白名单 LLM 源**（参赛手册 §3），多源降级 + 401/402 熔断 + 每题 token 预算 +
  重型模型升级策略（仅 HARD/VERY_HARD 或重试）。
- **作战脚本**：`scripts/_race_start.py --compete` = 抢一血 → 稳定轮询 → 收尾报告，
  内置**强制 e2e 数据链路预检（fail-closed，不过不开战）**。

## 硬门禁（事故教训的代码化）

| 门禁 | 内容 | 执行者 |
|------|------|--------|
| 测试门禁 | 真 pytest 运行（非逐文件假循环） | `setup.sh`（失败 exit 1） |
| e2e 门禁 | 平台真实给出题面/附件/靶机 | `scripts/_e2e_verify.py`（`--compete` 内置） |
| 网络门禁 | 代理存活 / LLM 端点直连 / 平台直连 | `scripts/_net_check.py`（trust_env=False） |
| 密钥门禁 | 暂存区明文密钥即拒 | pre-commit hook（`scripts/_scan_secrets.py`） |
| 写租约门禁 | 一个 scope 一个写者；越界提交直接拒 | `scripts/_lease.py` + pre-commit（CTDE 治理） |

## 快速开始

```bash
bash setup.sh                      # venv + 依赖 + 白名单 + 网络三查 + 测试门禁
python scripts/_e2e_verify.py      # 平台数据链路（平台开放时）
python scripts/_race_start.py --compete    # 作战模式（先跑 e2e 预检）
```

配置走环境变量（见 `config.py`）：`DASCTF_TOKEN`、`DASCTF_BASE_URL`、各 provider
API key。**密钥绝不进仓库**——hook 会拒。

## 目录

```
core/          主 Agent + 监督 + 预扫层
agents/        领域工具包（crypto/reverse/pwn/web/misc…）
ctfplatform/   DASCTF 客户端、poller、fail-open 提交链路
skills/        49 个确定性 skill + 基础数据
scripts/       作战脚本、e2e、网络三查、租约、密钥扫描
tests/         pytest 门禁（pytest.ini：-m "not slow" 为默认基线）
data/          赛题资产（入库）；运行时目录已 gitignore
AGENTS.md      治理铁律（任何 AI/人工会话开工前必读）
```

## 治理

本仓库在多 AI 会话并行协作下构建。事故驱动的成文规则见
[`AGENTS.md`](./AGENTS.md)；多会话协同协议（规范层）与写租约（执法层，
`scripts/_lease.py`）双层并存，冲突以执法层为准。完整赛后复盘文档保留在父目录
`deliverables/`（有意不入本仓库）。

### 协调状态从 git 派生（2026-08-24 · 阶段5）

`scripts/_board.py` 渲染**从 git 派生**的实时看板——分支列表（`w/*` 车道 = 开放任务）
+ 每车道 diff 统计 + `REAL_SOLVES_LEDGER.md` 计数。数据单向流动：git → 看板。
手工任务板/台账登记退役；写租约降级为**车道边界提示**（worktree 物理隔离才是真锁）。
唯一保留的自动记录段（post-commit 记账）作为提交归因的机器事实源。
