# 🧩 西湖论剑 CTF-Agent 模块骨架设计（v2.0 · 按专家锐评修订）

> **版本**：v2.0 | **日期**：2026-08-10 | **状态**：已按专家评估意见修订，可开工
> **v2.0 修订说明**：采纳专家锐评全部核心意见——
> ① 战略重心从「并发速度」转向「解出率优先」；② 砍掉 5 个独立子 Agent，改「1 主 1 监 + 领域工具包」；
> ③ 模板缓存/难度预分类从核心降级为辅助；④ 砍 Grafana/gVisor/向量库/多模型竞速/复杂测速报表；
> ⑤ 校验从「结果级」升级为「步骤级」；⑥ 平台 API 抽象做厚（全生命周期字段）。
> **阅读顺序**：`HANDOVER.md` → `ARCHITECTURE_PLAN.md` → 本文件 → `todo.md`

---

## 一、项目目录树（目标结构 v2.0）

```
E:\Program\西湖论剑\ctf_agent\
├── pyproject.toml                 # 项目配置（依赖：aiohttp/fastapi/httpx；docker 决赛前加）
├── run.py                         # 一键启动入口（CLI + Web 看板）
├── config.py                      # 配置加载（API Key、模型路由、限流参数）
│
├── core/                          # ★ 核心解题引擎（1 主 1 监，全部精力所在）
│   ├── __init__.py
│   ├── main_agent.py              # 主解题 Agent：通用推理内核（Plan-Act-Observe）
│   ├── supervisor_agent.py        # 监督反思 Agent：轻量模型，方向判断/僵局打断/策略切换
│   └── reasoning_loop.py          # ReAct 闭环编排：信息收集→漏洞判断→工具选型→执行验证→复盘→调整
│
├── agents/                        # ★ 领域工具包（工具按领域拆分，不是独立推理 Agent）
│   ├── __init__.py
│   ├── web_toolkit.py             # Web 工具包：SQLi/XSS/上传/SSRF/反序列化 payload 与工具链
│   ├── crypto_toolkit.py          # Crypto 工具包：RSA/AES/移位/哈希/爆破
│   ├── misc_toolkit.py            # Misc 工具包：隐写/编码/压缩包/取证
│   ├── reverse_toolkit.py         # Reverse 工具包（决赛冲刺）
│   ├── pwn_toolkit.py             # Pwn 工具包（决赛冲刺）
│   └── templates.py               # 辅助：典型场景快速 payload 生成（非核心得分项）
│
├── tools/                         # 工具协同层
│   ├── __init__.py
│   ├── registry.py                # 工具注册表（主 Agent 按需调用）
│   ├── base.py                    # ToolAdapter 抽象基类
│   ├── command_tool.py            # 通用命令行执行器（子进程隔离版，先做）
│   └── adapters/                  # 各工具适配器（先做 Web/Crypto/Misc 所需）
│       ├── sqlmap_adapter.py      # Web：SQL 注入
│       ├── zsteg_adapter.py       # Misc：图片隐写
│       ├── binwalk_adapter.py     # Misc：文件分析
│       ├── openssl_adapter.py     # Crypto：加解密
│       ├── gdb_adapter.py         # Reverse：调试分析（决赛）
│       └── pwntools_adapter.py    # Pwn：EXP 交互（决赛）
│
├── sandbox/                       # 沙盒执行层（子进程先行，Docker 决赛前）
│   ├── __init__.py
│   ├── executor.py                # 统一执行器接口
│   └── subprocess_executor.py     # 子进程隔离 + 30s 超时 kill（本机/MVP 用）
│                                   # docker_executor.py 决赛前补
│
├── verify/                        # ★ 步骤级校验-反馈层（v2.0 升级重点）
│   ├── __init__.py
│   ├── step_checker.py            # 步骤级校验：判断当前阶段、解析工具输出关键信息
│   ├── error_classifier.py        # 错误分类：僵局/方向错/幻觉/工具失败/环境失败
│   ├── feedback.py                # 结构化修正指令生成（不丢原始日志给模型）
│   └── flag_checker.py            # flag 格式验证 + 多格式提取
│
├── scheduler/                     # 基础并发调度（做到「多题不阻塞」即及格，不过度打磨）
│   ├── __init__.py
│   ├── task_pool.py               # asyncio 任务池：多题并行执行
│   ├── rate_limiter.py            # API 限流/熔断/超时/备用切换
│   └── model_router.py            # ★ 分级降级调度：轻量先试→失败升级重型（非竞速）
│
├── platform/                      # ★ 平台 API 抽象层（做厚，全生命周期字段）
│   ├── __init__.py
│   ├── base.py                    # PlatformAPI 抽象（创建/访问/附件/提交/重置/销毁）
│   └── dasctf.py                  # 测试赛当天实现 DasCTFPlatform
│
├── web/                           # 可视化看板（单页 HTML + 轮询，半天完成）
│   ├── __init__.py
│   ├── server.py                  # FastAPI 端点（任务/进度/flag）
│   └── static/
│       └── index.html             # 单页看板：进度/耗时/flag（原生 JS 轮询）
│
├── llm/                           # 复用 Security-Agent ai/client.py
│   ├── __init__.py
│   ├── client.py                  # ← 直接复用（多 provider、fail-open、JSON 提取）
│   └── mock.py                    # Mock 模式（无 Key 可跑）
│
├── eval/                          # 题库评测基准（复用评测思想）
│   ├── __init__.py
│   ├── benchmark.py               # 解出率/单题耗时/重试次数统计
│   └── cases.py                   # 本地测试题库加载
│
├── data/                          # 数据文件
│   ├── questions/                 # 本地测试题库（按题型分类）
│   ├── templates/                 # 典型场景 payload 模板（辅助）
│   └── results/                   # 解题结果/解出率报告
│
└── scripts/
    ├── _verify_syntax.py          # 语法检查（复用 Security-Agent 模式）
    └── _benchmark.py              # 题库跑分脚本（解出率优先统计）
```

## 二、核心架构：1 主 1 监 + 领域工具包（v2.0 重大变更）

### 为什么改（专家锐评要点）

| 原设计（v1.0） | 问题（专家指出） | v2.0 方案 |
|---|---|---|
| 5 个独立子 Agent | 复合题型边界模糊、11 天维护 5 套 Prompt 必然半成品 | **1 个主解题 Agent**（推理内核）+ 领域工具包 |
| 多模型竞速 | 简单题浪费、难题三家都解不出，成本翻 2-3 倍 | **分级降级调度**：轻量先试 → 解不出升级重型 |
| 模板缓存为核心 | 背题秒解≠AI 自主解题能力，评委不打分 | 降级为**辅助 payload 生成**，非得分项 |
| 难度预分类器 | 能精准分类≈已解一半，分类错误直接死锁 | **删除**，改为轻量题型识别（粗粒度 5 类） |
| Grafana/gVisor/向量库 | 11 天单人开发必然缩水成摆设 | **全部砍掉**，看板单页 HTML 轮询 |
| 结果级校验（flag 正则） | 模型不知道自己错在哪，重试=重复错误 | **步骤级校验**：判断阶段+解析输出+错误分类+定向修正 |

### 主解题 Agent（core/main_agent.py）

通用推理内核，走 **Plan-Act-Observe** 循环，负责分析题目、制定计划、调用工具、解读结果：

```python
class MainAgent:
    """主解题 Agent：通用推理内核，唯一的大脑。"""
    def __init__(self, llm, registry: ToolRegistry, sandbox: Executor,
                 router: ModelRouter): ...

    async def solve(self, question: Question, ctx: AgentContext) -> AgentOutput:
        """Plan-Act-Observe 循环，直到出 flag 或触发僵局。"""
        plan = await self.plan(question, ctx)            # 拆解任务：收集→判断→工具→验证
        while not ctx.is_stuck():
            act = await self.act(plan.next_step(), ctx)  # 执行一步（推理/调工具/跑脚本）
            obs = await self.observe(act, ctx)           # 解析执行结果，提取关键信息
            ctx.record(act, obs)                         # 结构化记录（供监督 Agent 评估）
            if self.checker.validate(ctx.candidate_flag()):
                return ctx.finish(flag=ctx.candidate_flag())
        return ctx.finish(error=ctx.last_error())        # 记录失败原因
```

### 监督反思 Agent（core/supervisor_agent.py）

轻量模型，**只做一件事**：每步执行后判断方向。负责打断僵局、触发策略切换：

```python
class SupervisorAgent:
    """监督反思 Agent：轻量模型，战略判断，不直接解题。"""
    async def review(self, step: StepRecord, ctx: AgentContext) -> SupervisionVerdict:
        """输入当前步骤的结构化摘要，输出裁决：continue / redirect / switch_strategy / give_up。"""
        # 判断维度（输入给轻量模型的是结构化摘要，不是原始日志）：
        # 1. 方向对不对（是否偏离题目目标）
        # 2. 是否死循环（连续 N 步同一动作/同一输出）
        # 3. 是否需要换思路（当前策略连续失败 K 次）
        # 4. 是否触发升级（轻量模型解不动 → 升级重型模型）
        ...

class SupervisionVerdict:
    action: str          # continue / redirect / switch_strategy / upgrade_model / give_up
    reason: str          # 结构化原因（供主 Agent 修正）
    suggestion: str      # 明确的修正方向（不是"再试一次"）
```

**触发策略**：主 Agent 每 2-3 步咨询一次监督 Agent（避免每次调用拖慢节奏）；连续失败 3 次强制咨询。

### 领域工具包（agents/*_toolkit.py）

工具按领域拆分，由主 Agent 按需调用：

```python
class WebToolkit:
    """Web 领域工具包：payload 模板 + 工具链。"""
    name = "web"
    tools = ["sqlmap_adapter", "http_client", "curl"]
    payload_templates = {             # 典型场景快速生成（辅助，非核心）
        "sqli": "...", "xss": "...", "upload": "...", "ssti": "{{7*7}} 探测", ...
    }
    def suggest_steps(self, question: Question) -> list[str]:
        """按题目描述/附件特征给出初始步骤建议（供主 Agent 参考，不强制）。"""
        ...
```

## 三、模块职责与关键类签名

### scheduler/ — 基础并发调度（"多题不阻塞"即及格）

```python
class TaskPool:
    """asyncio 任务池：多题并行执行，不做花哨优先级。"""
    def __init__(self, max_concurrency: int = 8): ...
    async def submit(self, question: Question) -> Task      # 入队
    async def run(self) -> list[Result]                     # 并行执行（信号量限流）

class RateLimiter:
    """API 限流/熔断/超时/备用切换。"""
    async def acquire(self, provider: str) -> None
    def record_failure(self, provider: str) -> None
    def switch_provider(self) -> str

class ModelRouter:
    """分级降级调度：轻量先试 → 失败升级重型（替代多模型竞速）。"""
    async def get_model(self, question: Question, attempt: int) -> str:
        # attempt 0-1: deepseek-v4-flash（轻量，快）
        # attempt 2-3: deepseek-v4-pro / qwen3-max（重型）
        # 连续失败才升级，控制成本
```

### verify/ — 步骤级校验-反馈（v2.0 核心升级）

```python
class StepChecker:
    """步骤级校验：判断当前阶段、解析工具输出关键信息。"""
    def parse_tool_output(self, output: ExecResult) -> ParsedOutput:
        """从原始 stdout 提取关键信息（行数裁剪/正则抽取/结构摘要）。"""
    def judge_stage(self, ctx: AgentContext) -> str:
        """当前处于哪个阶段：recon / exploit / flag_extract / stuck"""

class ErrorClassifier:
    """错误分类（决定修正策略，而非盲目重试）。"""
    CATEGORIES = {
        "stuck_loop":      "连续 N 步同一动作/输出，死循环",
        "wrong_direction": "偏离题目目标（如分析错文件/错端口）",
        "hallucination":   "编造输出（flag 未经验证/工具未执行就断言）",
        "tool_failure":    "工具执行失败（命令不存在/超时/语法错）",
        "env_failure":     "环境问题（依赖缺失/网络不通）",
    }
    def classify(self, step_history: list[StepRecord]) -> ErrorCategory

class FeedbackLoop:
    """结构化修正指令生成：不给模型原始日志，给错误分类 + 修正方向。"""
    async def run(self, agent: MainAgent, question: Question, max_retries: int = 3) -> AgentOutput:
        for attempt in range(max_retries):
            output = await agent.solve(question, ctx)
            if self.checker.validate(output):
                return output
            error = self.classifier.classify(ctx.steps)          # ① 错误分类
            verdict = await supervisor.review(ctx.last_step())   # ② 监督裁决
            ctx.apply_correction(error, verdict)                 # ③ 结构化修正指令
        return output
```

### platform/ — 平台 API 抽象（做厚，全生命周期）

```python
class PlatformAPI(ABC):
    """官方答题平台抽象——覆盖完整题目生命周期，不做假设性硬编码。"""
    async def list_challenges(self) -> list[ChallengeInfo]: ...
    async def get_challenge(self, challenge_id: str) -> ChallengeInfo: ...
    async def create_instance(self, challenge_id: str) -> InstanceInfo:   # 启动容器/实例
    async def get_access(self, instance_id: str) -> AccessInfo:           # 访问地址/端口/账号
    async def download_attachment(self, challenge_id: str) -> list[str]:  # 附件下载
    async def get_hint(self, challenge_id: str) -> str: ...
    async def submit_flag(self, challenge_id: str, flag: str) -> SubmitResult: ...
    async def reset_instance(self, instance_id: str) -> None:             # 环境重置
    async def destroy_instance(self, instance_id: str) -> None:           # 销毁实例

class ChallengeInfo:
    id: str
    title: str
    category: str              # web/crypto/misc/reverse/pwn
    description: str
    flag_format: str           # 如 flag{...} / DASCTF{...}
    score: int                 # 分值（优先级参考）
    has_instance: bool         # 是否需要启动实例
    has_attachment: bool

class SubmitResult:
    accepted: bool
    correct: bool              # accepted=true 视为完成
    detail: str
    remaining_attempts: int    # 提交次数限制（如有）
```

**设计原则**：上层只依赖抽象字段，所有字段带默认值；测试赛拿到真实 openapi.json 后仅实现 `DasCTFPlatform` 一个类。

## 四、统一 JSON 契约（全链路核心，v2.0 扩展）

```json
{
  "task_id": "TASK-0001",
  "question_type": "crypto",
  "stage": "exploit",               // 当前阶段：recon/exploit/flag_extract
  "flag": "flag{...}",              // 校验通过后填充
  "confidence": 0.87,
  "evidence": ["检测到 RSA 公钥 e=65537", "n 可分解，p/q 已提取"],
  "error": {
    "category": "hallucination",    // 错误分类（v2.0 新增）
    "detail": "模型未执行工具即断言结果"
  },
  "supervision": "redirect",        // 监督裁决（v2.0 新增）
  "duration_ms": 1234,
  "provider": "deepseek-v4-flash",
  "retries": 2
}
```

## 五、数据流（一道题从提交到出 flag，v2.0）

```
1. 批量导入赛题 → POST /api/tasks
2. TaskPool.submit() → 并行入队（信号量 ≤8）
3. MainAgent.solve()：Plan-Act-Observe 循环
   a. plan：按题目特征（描述/附件/flag_format）生成步骤计划
   b. act：执行一步——模型推理 / 调领域工具包 / 沙盒跑脚本（ModelRouter 选模型）
   c. observe：StepChecker.parse_tool_output() 提取关键信息（不丢原始日志）
   d. 每 2-3 步 / 连续失败 3 次 → SupervisorAgent.review() 给裁决
4. FeedbackLoop：
   a. FlagChecker.validate() 验证 flag
   b. 失败 → ErrorClassifier.classify() 分类 → 结构化修正指令回传（≤3 次）
5. 出 flag → SubmitResult.accepted → 记录耗时/重试次数
6. 结果写 data/results/ → Web 看板轮询刷新
```

## 六、关键设计决策清单（v2.0，对照专家意见）

| # | 决策 | 状态 | 说明 |
|---|------|------|------|
| 1 | 解出率优先，并发只做到"多题不阻塞" | ✅ 采纳 | 排名看解出分值，不看快几秒；调度层不做优先级队列/毫秒测速打磨 |
| 2 | 1 主 1 监架构替代 5 子 Agent | ✅ 采纳 | 主 Agent 推理内核 + 监督 Agent 轻量裁决 + 领域工具包 |
| 3 | 分级降级调度替代多模型竞速 | ✅ 采纳 | 轻量先试→失败升级重型，成本可控，效果等价 |
| 4 | 模板缓存降级为辅助 | ✅ 采纳 | 作为 payload 快速生成工具，不当作核心创新 |
| 5 | 删除难度预分类器 | ✅ 采纳 | 改为轻量粗粒度题型识别（5 类），不做难度预测 |
| 6 | 步骤级校验替代结果级校验 | ✅ 采纳 | 错误分类 + 监督裁决 + 结构化修正指令 |
| 7 | 砍 Grafana/gVisor/向量库/测速报表 | ✅ 采纳 | 看板单页 HTML 轮询，半天完成 |
| 8 | 平台 API 抽象做厚（全生命周期） | ✅ 采纳 | 创建/访问/附件/提交/重置/销毁全字段，测试赛只填实现 |
| 9 | 复用 Security-Agent 资产 | ✅ 保留 | llm/client.py、triage 防御解析、evaluation、web/server 思路 |

## 七、MVP 范围（初赛 8/21 前必交付）

| 模块 | MVP 内容 | 优先级 |
|------|---------|--------|
| core/ | MainAgent + SupervisorAgent + reasoning_loop | ✅ 必做（核心） |
| platform/ | PlatformAPI 抽象 + 测试赛实现 | ✅ 必做 |
| sandbox/ | subprocess_executor（30s 超时） | ✅ 必做 |
| verify/ | step_checker + error_classifier + feedback + flag_checker | ✅ 必做 |
| agents/ | web/crypto/misc 三工具包 | ✅ 必做 |
| scheduler/ | task_pool（简单并行）+ rate_limiter + model_router | ⚠️ 基础版即可 |
| web/ | 单页看板（进度/耗时/flag） | ⚠️ 半天完成 |
| llm/ | client 复用 + mock | ✅ 必做 |
| reverse/pwn | 决赛冲刺 | ❌ 初赛不做 |

## 八、验收标准（骨架设计合格的定义，v2.0）

1. **解出率可量化**：本地题库（Web/Crypto/Misc 各 5 题）跑分，记录解出率/耗时/重试次数
2. **步骤级反馈生效**：构造一个模型幻觉场景（未执行工具就报 flag），能触发错误分类+监督裁决+定向修正
3. **分级降级生效**：Mock 模式轻量模型连续失败后能升级重型模型（或 Mock 标记升级）
4. **平台抽象完整**：测试赛拿到 openapi.json 后，仅实现 DasCTFPlatform，不动上层
5. **可演示**：单页看板一键启动，评委可批量导题、实时看进度与 flag
