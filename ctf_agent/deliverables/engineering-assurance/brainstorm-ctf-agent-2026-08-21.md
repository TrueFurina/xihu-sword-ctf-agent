# 🧠 西湖论剑 CTF-Agent 赛前全员头脑风暴报告

**日期**：2026-08-21（开赛当日上午，距 14:00 开赛约 12 小时）
**工作流**：全员头脑风暴（架构 / 代码 / 可靠性 / 测试 / 文档 五视角并行）
**参与成员**：Cody（代码审查师）/ Archi（系统架构师）/ Rex（SRE 工程师）/ Tessa（测试专家）/ Docu（技术文档师）—— 全部实读源码或实测验证

---

## 📌 TL;DR（执行摘要）

- **整体结论**：架构骨架（1 主 1 监 + 步骤级校验 + 墙钟止损）是对的，但**五条"保护线"没有一条真正接到真实求解链路上**——分级升级空转、限流/熔断是死代码、启动命令与手册脱节、沙盒存在已实证的绕过、假阳性自判信号无人对账。赛前 12h 的胜负手不是加新特性，而是"接通已有的保护线 + 堵住已实证的洞"。
- **严重度分布**：🔴严重 6 项 / 🟠高 6 项 / 🟡中 3 项 / 🟢低 2 项
- **阻塞 / 非阻塞**：🔴 6 项 P0 为开赛阻塞项（启动命令、升级空转、限流、沙盒、400 兜底、余额复核），非阻塞项为赛前可选优化与赛后/决赛准备
- **三方交叉印证**：限流/熔断未接线（Cody/Archi/Rex 独立发现，同一代码事实：`RateLimiter.acquire()` 全项目零调用）

---

## 🎯 核心结论卡片

| 项目 | 内容 |
|------|------|
| 整体评级 | 🟡 有条件通过（代码能力真实，但 P0 未闭环前开赛有翻车风险） |
| 阻塞项数量 | 🔴 6 项 P0（赛前 12h 内可全部闭环） |
| 关键行动项 | 10 条（P0×6 + P1×4） |
| 建议下一步 | 按行动清单 #1→#6 顺序执行，做完 #10 全链路演练后冻结代码 |

---

## 🔍 头脑风暴核心发现（按主题，已跨成员去重合并）

### 一、开赛级 P0（不修 = 开赛翻车）

| # | 发现 | 代码/位置 | 来源 |
|---|------|----------|------|
| P0-1 | **启动命令与手册脱节（已实测）**：手册/setup.sh 写 `run.py --race`/`--web`，但 run.py argparse 只认 `--mode cli/web/verify/platform`，实测报 `unrecognized arguments`。正确入口 = `scripts/_race_start.py --compete` + `run.py --mode web`。**收敛决策：冻结代码，不改 run.py**——距开赛 12h 内只固化 `_race_start.py --compete` 为唯一启动命令并写 start_race.bat（绝对路径+日志重定向） | run.py argparse / setup.sh / 赛前作战手册 | Rex |
| P0-2 | **分级升级空转（胜负手）**：`get_model_for_attempt(attempt, provider)` 在 provider 非空时直接返回默认模型（run.py:118 恒传 provider）→ attempt≥2 的重型深推理**永不触发**。**叠加死代码（O1 修正版，Archi×Rex 实测交叉验证）**：main_agent.py:187（高难首步重型）与 :380（分级墙钟 `_wallclock_for`）都读 `(question.extra or {}).get("difficulty")`，但 Question dataclass（eval/cases.py:31）只有 difficulty、**没有 extra 字段** → 恒为空：所有题一律走默认 300s 墙钟。**修复是三点联动（同一 commit 缺一不可）**：① main_agent.py:187 改读 `getattr(question,"difficulty","")`；② :380 同改；③ run.py build_platform_solver（L434-440）构造 Question 时补 `difficulty=str((ch.extra or {}).get("difficulty",""))`。⚠️**致命陷阱**：Question.difficulty 默认值="easy"，若只改 ①②而漏改 ③，平台题全部落默认 "easy" → 墙钟全走 120s，比现在统一 300s 更惨（HARD 被 120s 掐死，解出率崩盘）。**防守性默认值**：_wallclock_for 对空/未知难度回落 300s（MEDIUM），仅显式 EASY/VERY_EASY→120s、HARD/VERY_HARD→600s；改前先 `_race_start.py --probe` 确认平台真带 difficulty（不返回则降级为统一 300s 不强行分级）；加回归单测（hard→600s+attempt2；空→300s）。成本含 probe+单测约 1h | scheduler/model_router.py / main_agent.py:187,380 / eval/cases.py:31 / run.py:118,434-440 | Archi+Rex |
| P0-3 | **限流/熔断是死代码**：`RateLimiter.acquire()` 全项目无 import（仅测试用），8 并发直打单 provider，429/超时 → fail-open 每失败烧 1 推理回合，无备用切换。**收敛方案（Rex×Archi 复核）**：`run.py --mode platform` / `_race_start --compete` 的 build_solver 是单 provider（deepseek）零冗余 → 把 build_platform_solver 的 core_solver 换成最小竞速 `build_race_solver(providers=("deepseek","baidu"), models=(), tokenhub_models=(), extra_models=())`（并行兜底无回退延迟、baidu 免费白名单、成本 2×；因 poller 并发硬编码 2，实际只有 2题×2provider=4 条链，不会爆 429）。**若赛前不改代码**：最低限度靠 `_emergency.py --downgrade` 手动切 baidu（分钟级丢分窗口） | scheduler/rate_limiter.py / run.py:117 | Cody+Archi+Rex |
| P0-4 | **沙盒 AST 绕过已实证**：subprocess_executor.py:83-91 只查 `Attribute.attr`，`getattr(__import__("os"),"system")("id")` 实测放行（__import__/getattr 均不在 _FORBIDDEN_CALLS）；非 python: 前缀的 bash -c 路径完全无校验。**风险：题目内容可注入 → 读 .env/注册表 Key → 经 httpx 外带** | sandbox/subprocess_executor.py:83-91 | Cody |
| P0-5 | **400 无兜底**：已知硬伤①（prompt 层 400）只有日志没有预防性降级；plan prompt 附件 base64/hex 全文进上下文 | llm/client.py _post_chat / prompts.py | Archi+Cody |
| P0-6 | **余额漂移未复核**：config 默认注释写"deepseek/qwen 已欠费(08-19)"，手册称 08-20 充值——若实际欠费，402 全挂 | config.py / 赛前作战手册 | Rex |

### 二、高优先级 P1

| # | 发现 | 应对 | 来源 |
|---|------|------|------|
| P1-1 | **假阳性机制代码级定位**：goal_log 的 ✅ 是 `entry.flag 非空即判`（goal_directive.py:266），786 条 validated 全 false；答案校验在 run.py 外层（run.py:169-183），两层从未打通。real_reverse_js"3 次✅校验❌"即此机制 | 赛中唯一权威 = 平台 accepted（poller.py:353）；实时对账 `有flag数 − accepted数` = 幻觉候选 | Tessa |
| P1-2 | **幻觉 flag 烧提交次数**：平台模式 `is_correct=lambda True`，幻觉 flag 直接提交消耗配额 | 加 evidence 门控提交（无工具产出链的 flag 降级待人工），保留 5 连败熔断 | Archi |
| P1-3 | **EASY 墙钟 vs LLM 超时张力**：EASY 墙钟 120s 但单步读超时 120s，慢步直接烧穿预算 | 赛前 `CTF_AGENT_LLM_TIMEOUT` 降至 45-60s | Archi |
| P1-4 | **平台字段差异未核对**：`_parse_challenge` 无 category 默认 misc（web 题走 misc 兜底 = 解出率归零）、get_access 只认 entrypoints[0] dict | 开赛 10min 内 list+get_challenge dump 原始 JSON 人工核对映射 | Archi |
| P1-5 | **文档口径五处打架**：真实水位 60%/50%/33%/17%/25% 五个版本；sensenova 白名单结论已反转但作战手册没更正；slide-outline.md 竟是《我的世界》PPT 大纲；"28 Skill"（实为 34） | 一数定音（答辩建议用 33%+假阳性机制故事，更可信）、一文为尊、旧档冻结 | Docu |
| P1-6 | **双进程冲突**：--race 与 --web 同机 = 双份 solver 双倍 API + 8000 端口冲突 + goal_log 双写交错 | 单引擎策略（web 作唯一引擎 或 只跑 _race_start） | Rex |

### 三、中优先级 P2（可选优化）

| # | 发现 | 应对 | 来源 |
|---|------|------|------|
| P2-1 | JSON 解析鲁棒性：_extract_json_object 仅 fence 剥离+{}截取，尾逗号/单引号 key 即失败 | 轻量 repair pass（去尾逗号、单引号→双引号），~15 行，每救回 1 次 = 省 1 推理回合 | Cody |
| P2-2 | token/400 缓解：observation[:500] 与 MAX_OUTPUT_CHARS=500 可降 300；messages 无总字符护栏 | 降截断值 + ai_chat 入口加护栏 | Cody |
| P2-3 | 看板 solved 虚高：/api/metrics 的 solved = "有 flag 即 solved" | 只当趋势不当解出数；赛后区分"自判 vs 校验"两层展示 | Tessa+Docu |
| P2-4 | poller max_concurrency 硬编码 2 未参数化（**已确认：CTF_AGENT_MAX_CONCURRENCY 对它无效，是死配置，别去调**）；data/platform_downloads 附件按 basename 缓存会串文件（同文件名覆盖）→ **开赛前清空该目录**，否则跨题附件串文件 | ctfplatform/poller.py | Archi+Rex |

### 四、低优先级 / 已知无害

- config.py 重复 `_env_or_registry`（42/270）与重复 ark 分支（222/259）：死代码，赛中勿动（Cody）
- 预算记账失真：`est=len(hint)//4+200` 每次只记 ~200 token，per_question_token_budget 需 400 次重试才触发——墙钟已是主闸，不值得赛中动（Cody）

---

## 🔄 复核收敛补充（Rex × Archi 复核后回传，2026-08-21 02:20）

- **主路径冗余方案定稿**：`run.py --mode platform` / `_race_start --compete` 用 build_solver 单 provider（deepseek）零冗余 → 改 build_platform_solver 的 core_solver 为最小竞速 `build_race_solver(providers=("deepseek","baidu"))`；不改代码则最低限度 `_emergency.py --downgrade` 手动切（分钟级丢分窗口）
- **入口统一定稿**：12h 内不改 run.py，固化 `_race_start.py --compete` 唯一命令 + start_race.bat
- **O5 确认**：poller max_concurrency 恒为 2（CTF_AGENT_MAX_CONCURRENCY 是死配置，别去调）；data/platform_downloads 附件按 basename 缓存会串文件 → 开赛前清空
- **止损口径统一**：poller 超时 600/1200/1800s 只是兜底，实际止损靠 main_agent 墙钟 120/300/600s——**所有文档以墙钟为准**
- **O1 修正版（Archi×Rex 实测交叉验证，覆盖早前"一行修复"表述）**：分级墙钟/高难首步重型死代码的修复是**三点联动**（同一 commit 缺一不可）：① main_agent.py:187 改读 `getattr(question,"difficulty","")`；② :380 同改；③ run.py build_platform_solver（L434-440）构造 Question 时补 difficulty。⚠️**致命陷阱**：Question.difficulty 默认="easy"，漏改 ③ 则全题落 120s 墙钟（比统一 300s 更惨，HARD 被掐死）→ 必须同 commit 齐改，且 ③ 缺失时传空串而非默认。防守性默认值：_wallclock_for 对空/未知回落 300s，仅显式 EASY→120s、HARD→600s；改前先 `--probe` 确认平台带 difficulty（无则降级统一 300s）；加回归单测防复发。P0，含 probe+单测约 1h

## 🛡️ 赛中监控（3 小时实时）

### 5 个健康指标（Tessa）
1. **平台 accepted 数**（唯一权威）：submitted_flags.json / poller 报表；节奏参考 15-20min/题，首小时应 2-4 题
2. **假阳性率** = (goal_log 有 flag − accepted) / goal_log 有 flag；**>30% 告警**（在烧幻觉）
3. **止损分布**：goal_log error.category 计数；stuck_loop + wallclock 占比 >40% 或连续 3 题 wallclock → 退化
4. **400/429/402 次数**：grep 日志计数；飙升 = 模型配置漂移（查 LIGHT_MODEL）或余额问题
5. **耗时分布**：解出题中位耗时、最长单题；中位 >5min 或 >10min 失控 → 退化

### 4 类故障止损 SOP（Rex）
- **大面积 400**：① grep "HTTP 400" 看 payload.model → 核对 provider/LIGHT_MODEL 配套、截断 observation/降 max_tokens ② 持续则 `_emergency.py --downgrade`
- **provider 全挂**：① `_emergency.py --status` ② `_provider_failover.py --auto` ③ --downgrade + 重启；全挂切 `--mock` 保链路
- **看板翻车**：① 查 8000 端口占用 kill 多余进程 ② 收敛单引擎 ③ 看板挂不影响解题（goal_log 仍写），tail 日志应急，赛后 --mode web 重开
- **venv 又坏**：① 绝不碰 managed python ② import httpx 判损 ③ `bash setup.sh` 重建（赛前先备份 .venv_bak）

---

## ✅ 行动清单（按优先级排序）

| # | 行动 | 负责角色 | 紧急度 | 预期完成 |
|---|------|---------|--------|---------|
| 1 | 统一启动入口（**冻结代码，不改 run.py**）：固化 `_race_start.py --compete` 为唯一启动命令，写 start_race.bat（绝对路径+日志重定向），开赛前清空 data/platform_downloads | Rex+Cody | P0 | 赛前 1h |
| 2 | 修升级空转 + 分级墙钟死代码（**三点联动修复包，同一 commit 缺一不可**）：① get_model_for_attempt 加 provider→heavy 映射；② main_agent.py:187/:380 改读 `getattr(question,"difficulty","")`；③ run.py build_platform_solver（L434-440）补 difficulty（**漏 ③ 全题落 120s，比现状更惨**）；_wallclock_for 空/未知回落 300s；改前 `--probe` 确认平台带 difficulty；加回归单测 | Archi+Rex | P0 | 赛前 3h |
| 3 | 接通限流：run.py llm_client 包 asyncio.Semaphore(4~6) + 连续失败切 provider（~20 行，替代死代码 RateLimiter） | Cody+Archi | P0 | 赛前 3h |
| 4 | 堵沙盒绕过：__import__/getattr 加入禁名 + 字符串常量扫 os.system/subprocess + bash 路径校验（备份后改，可秒回滚） | Cody | P0 | 赛前 2h |
| 5 | 400 兜底：_post_chat 捕获 400 降级重试（剥控制字符/obs 截 300 字）+ plan 附件改摘要 | Archi+Cody | P0 | 赛前 4h |
| 6 | 余额/Key 实测：_provider_failover.py --check 验证 deepseek-chat 200 + 备份 4 个 key + 脱敏 data/results + 确认 ENFORCE_WHITELIST=1 | Rex | P0 | 赛前 2h |
| 7 | 一数定音：统一水位口径（答辩用 33% + 假阳性机制故事）+ 作战手册 sensenova 更正 + skill 数统一 34 + 冻结旧文档 | Docu | P1 | 赛前 4h |
| 8 | LLM 超时 120s→45-60s + 平台结构核对（category/entrypoints 映射，开赛 10min 内 dump 原始 JSON） | Archi | P1 | 赛前 2h |
| 9 | 赛中监控脚本：grep -cE "HTTP (400\|429\|402)" + goal_log 对账脚本（有flag−accepted，量化假阳性率），赛前跑通 | Rex+Tessa | P1 | 赛前 3h |
| 10 | 全链路演练一次：--check → _drill_failover.py --down deepseek → --once 真提 1 题，stdout 重定向落盘，记录基线 | Rex | P1 | 赛前 2h |

---

## 📚 赛后 / 决赛准备

### 赛中证据链（Docu，★=答辩最值钱）
- goal_log.jsonl【已有】786 行，天然区分"自判(flag)"与"校验(validated)"两层——对抗假阳性的核心证据；⚠️ 确认 validated=false 语义（未校验/三态REJECT/比对失败）三选一
- submitted_flags.json【已有】⚠️ 混入 mock 脏数据，赛后清洗
- --web 看板【已有】⚠️ 无截图钩子 → 赛中每 30min 人工截图或临时 --snapshot
- 每题最终裁决汇总表【缺失】→ 赛后从 goal_log 聚合"官方比对/三态/墙钟/error 归因"一张表
- 3h 作战时间线【缺失】记录首题解出/故障/止损关键时刻
- 白名单合规留存【缺失】preflight exit=0 + provider 调用日志 → "三道防线"举证
- 汇总为 `data/results/证据_20260821/` 答辩素材夹【缺失】

### 决赛答辩叙事线（Docu）
1. 定位："把人的安全解题能力沉淀为 Agent 系统能力"——不是模型强，是 1 主 1 监 + 34 skill + 工具前置证据闭环
2. 诚实水位：自出题 74% 仅验证链路，独立真题彩排真实水位 33%（以独立答案校验为准），主动暴露自判假阳性被校验兜住——用机制对抗幻觉
3. 三道防线（运行时闸门+解析期强制禁用+preflight）做成代码级事实，主动承认并修正 sensenova 文档矛盾
4. 三创新点 + 墙钟止损实证（120/300/600s 分级）
5. 3h 真实作战时间线 + 看板截图收尾——"跑过的系统"而非 PPT

### 决赛架构演进（Archi）
1. Docker 沙盒 + 证据链审计回放（决赛跑不可信二进制，答辩要可追溯）
2. 领域 Agent 并行攻坚替代单主串行（保留监督与预算闸）
3. 赛中知识复用：goal_log 失败模式 → 同题型自动加载 skill/修正策略，3h 内学习闭环

---

## ⚠️ 待完善 / 已知局限

- **赛前纪律红线**：25k 行代码、15 个测试对三处零覆盖——llm/client.py、run.py solver 包装层、ctfplatform/poller.py。任何改动都是拿晋级换风险，只验证不动手
- **测试盲区**：改 config.py → scheduler×3+wallclock×4+integration×2 兜底；改 report/generator → honesty×3；改 main_agent._finalize → wallclock×4+integration×2；其余文件改动无测试兜底
- **不建议赛前做**：新增 tests/ 文件、改 GoalLogger 让 validated 回写 goal_log（改已验证链路）、改并发/预算参数（可赛中 env 调）、动 flag_checker 与主循环（一改全崩）
- **余额漂移是最不确定项**：以 #6 实测为准，备选 baidu（千帆免费）兜底

## 📚 数据来源 & 成员产出索引

- Cody（代码审查师）原始产出：沙盒绕过实证 / 限流死代码 / JSON 鲁棒性 / 热修安全区-禁区清单
- Archi（系统架构师）原始产出：升级空转定位 / 400 兜底 / evidence 门控 / 平台字段差异 / 决赛演进
- Rex（SRE 工程师）原始产出：启动命令实测 P0 / 就绪检查清单 / 4 类故障 SOP / 证据清单
- Tessa（测试专家）原始产出：假阳性机制代码级定位 / 测-不测-只验证三分类 / 5 健康指标
- Docu（技术文档师）原始产出：口径冲突盘点 / 证据链设计 / 答辩叙事线

---

> 本报告由工程保障团队 AI 协作生成，关键决策请由人类工程负责人复核。
> ⚠️ 特别提醒：P0-1（启动命令）与 P0-4（沙盒绕过）为成员**实测验证**结论，建议赛前优先复核并闭环。
