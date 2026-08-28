# Final Proposal: 竞赛态势感知 + 动态资源分配的赛智 CTF-Agent

**Date**: 2026-08-27
**Idea Rank**: #4 RECOMMENDED (填补空白 #4)
**Target Venue**: 西湖论剑 AI-CTF 赛道 / 安全学术会议

---

## 1. Problem Anchor

### 1.1 赛制约束（西湖论剑 AI-CTF）

| 约束 | 值 | 影响 |
|------|-----|------|
| 比赛时长 | 3 小时 (180 min) | 决策窗口极短，每分钟机会成本高 |
| 题目数量 | 40+ 道 | 不可能全部解出，必须做取舍 |
| Token 预算 | 有限（DeepSeek/千问 API 计费） | 资源耗尽 = 被迫停赛 |
| 运行环境 | Windows，无 Docker | 不能依赖容器化隔离 |
| 评审方式 | 实时演示看板 | 需要可观测的决策过程 |

### 1.2 现有方案的根本缺陷

**所有现有 AI-CTF 项目的资源分配都是静态的**：

- **hydra**（华沙大学）的 cost-cap 是固定阈值，不会根据剩余时间或已解题数调整
- **LLM-CTF-Solver** 的双熔断仅基于 token 消耗，不感知竞赛进程
- **SageCTF**（DEF CON 前 5%）的自生成拓扑在开赛后不再变化
- **本项目** `race_strategy.py` 有先易后难排序，但**排序在开赛时固化，不感知竞赛进程**

人类选手在比赛中会动态调整策略：
1. 发现某题卡住 → 立即换题，不浪费时间
2. 剩余时间紧迫 → 只做有把握的题
3. 预算紧张 → 降级到轻量模型
4. 看到对手解出某题 → 调整优先级

**AI-CTF 领域的结构性空白**：没有项目将竞赛态势感知与资源分配联动。

### 1.3 问题形式化

给定：
- 题目集合 $Q = \{q_1, q_2, \ldots, q_n\}$，每题有分值 $s_i$ 和类别 $c_i$
- 总时间 $T = 180$ 分钟，总预算 $B$ tokens
- 模型集合 $M = \{m_{\text{heavy}}, m_{\text{light}}, m_{\text{tiny}}\}$，各有成本 $b_m$ 和能力 $a_m$

目标：在约束 $t_{\text{total}} \leq T$ 和 $b_{\text{total}} \leq B$ 下，最大化期望总分：

$$\max \sum_{i=1}^{n} s_i \cdot \mathbb{1}[\text{solved}(q_i)]$$

核心难点：解题概率 $p_i$、耗时 $t_i$、资源消耗 $b_i$ 均为**未知且随时间变化**的随机变量，需要在线估计。

---

## 2. Method Thesis

### 2.1 核心论点

**在限时 CTF 竞赛中，通过三维态势感知（微观/中观/宏观）实时估计每道题的边际收益，动态调整资源分配（模型等级、并发数、单题预算），可在固定总预算下将解出数提升 20-40%。**

### 2.2 三层态势感知引擎

#### 第一层：微观态势（单题信心）

对正在求解的每道题 $q_i$，维护一个**解题信心分数** $C_i(t) \in [0, 1]$：

$$C_i(t) = \alpha \cdot H_i(t) + \beta \cdot P_i(t) + \gamma \cdot D_i(t)$$

其中：
- $H_i(t)$：**历史进展分数** — 最近 $k$ 步中产生新线索的比例
  - $H_i(t) = \frac{\text{最近 } k \text{ 步中新线索数}}{k}$，$k = 5$
  - "新线索"定义：工具输出中出现之前未见过的 URL/函数名/内存地址/字符串
- $P_i(t)$：**模式匹配分数** — 当前解题路径与已知成功模式的相似度
  - 基于 `error_classifier.py` 的 5 类分类：若最近步骤的错误类别从 "stuck_loop" 转向 "continue"，$P_i$ 上升
  - $P_i(t) = \sigma(w^T \cdot \text{error\_history}_i(t))$，$\sigma$ 为 sigmoid
- $D_i(t)$：**难度估计分数** — 基于已消耗资源与预期的比值
  - $D_i(t) = \exp\left(-\frac{b_i(t)}{b_{\text{expected}}(c_i)}\right)$，指数衰减
  - $b_{\text{expected}}(c_i)$ 为该类别题目的历史平均消耗

权重：$\alpha = 0.4, \beta = 0.35, \gamma = 0.25$（通过消融实验确定）。

**降级规则**：当 $C_i(t) < 0.3$ 且已消耗超过 $50\%$ 单题预算时，触发换题。

#### 第二层：中观态势（全局进度）

维护全局状态向量 $S(t)$：

```
S(t) = {
    solved:        int,        # 已解出题数
    active:        int,        # 正在求解的题数
    stuck:         int,        # 卡住的题数
    abandoned:     int,        # 已放弃的题数
    total:         int,        # 总题数
    budget_used:   float,      # 已消耗 token 比例
    budget_rate:   float,      # token 消耗速率 (tokens/min)
    time_used:     float,      # 已用时间比例
    time_remaining: float,     # 剩余时间 (min)
    solve_rate:    float,      # 解题速率 (题/min)
    eta_budget:    float,      # 预计预算耗尽时间
    eta_finish:    float,      # 按当前速率完成所有题的时间
}
```

关键指标：
- **资源压力指数** $\text{RPI}(t) = \frac{\text{budget\_rate} \times \text{time\_remaining}}{\text{budget\_remaining}}$
  - $\text{RPI} > 1$：按当前速率，预算将在比赛结束前耗尽 → 触发降级
  - $\text{RPI} < 0.5$：预算充裕 → 可以升级模型

#### 第三层：宏观态势（边际收益）

对每道未解出的题 $q_i$，计算**边际收益**（Marginal Value）：

$$\text{MV}_i(t) = \frac{s_i \cdot \hat{p}_i(t)}{\hat{t}_i(t)}$$

其中：
- $s_i$：题目分值（已知）
- $\hat{p}_i(t)$：**估计解出概率**
  - 对于未开始的题：$\hat{p}_i(0) = p_{\text{base}}(c_i)$，基于该类别的历史解出率
  - 对于进行中的题：$\hat{p}_i(t) = C_i(t) \cdot p_{\text{base}}(c_i)$，信心分数修正
- $\hat{t}_i(t)$：**估计剩余耗时**（分钟）
  - 对于未开始的题：$\hat{t}_i(0) = t_{\text{avg}}(c_i, m)$，基于该类别+模型的历史平均耗时
  - 对于进行中的题：$\hat{t}_i(t) = t_{\text{avg}}(c_i, m) \cdot (1 - C_i(t))$，信心越高剩余越少

**边际收益的理论基础**：

边际收益公式 $\text{MV}_i = s_i \cdot \hat{p}_i / \hat{t}_i$ 可以从两个理论框架推导：

1. **Multi-Armed Bandit (MAB)**：将每道题视为一个臂（arm），拉臂收益为 $s_i \cdot p_i$，拉臂成本为 $t_i$。在有限时间 $T$ 内最大化收益，等价于选择**收益/成本比最高**的臂。这正是 $\text{MV}_i$ 的定义。UCB1 算法的变体 UCB1-Tuned 会自动平衡探索（低置信度题）与利用（高边际收益题）。

2. **最优停止理论（Secretary Problem 变体）**：在 $n$ 道题中依次选择，每道题有随机收益。经典结论：观察前 $n/e \approx 37\%$ 的题后，选择第一个超过观察期最大值的题。在 CTF 场景中，"观察期"对应开赛后前 40 分钟的探索阶段，之后进入"选择期"——只做边际收益高于阈值的题。

---

## 3. Core Claims（可证伪 + 证据需求）

### Claim 1: 动态资源分配可将解出数提升 20%+

**可证伪条件**：在 40 道标准化 CTF 题上，动态分配的解出数与静态分配无显著差异（$p > 0.05$，双侧 $t$ 检验）。

**证据需求**：
- 在 10 轮重复实验（固定 seed）中，动态分配平均解出数 > 静态分配 × 1.2
- 效果量 Cohen's $d > 0.5$（中等效应）

**消融维度**：
- C1a: 仅微观态势（单题信心）→ 换题决策改进
- C1b: 仅中观态势（全局进度）→ 资源压力感知
- C1c: 仅宏观态势（边际收益）→ 优先级排序改进
- C1d: 三层联动 → 完整方案

### Claim 2: 边际收益驱动的换题策略优于超时换题

**可证伪条件**：在相同时间约束下，边际收益换题的解出数与超时换题无显著差异。

**证据需求**：
- 边际收益换题的平均解出数 > 超时换题 × 1.15
- 浪费在"注定失败"题目上的 token 减少 30%+

**消融维度**：
- C2a: 固定超时 90s 换题（当前 baseline）
- C2b: 信心阈值 < 0.3 换题
- C2c: 边际收益排序换题（完整方案）
- C2d: 边际收益 + 探索预算（UCB 式探索）

### Claim 3: 紧急模式可在最后 30 分钟挽回 15%+ 的分数

**可证伪条件**：模拟"最后 30 分钟"场景，紧急模式的得分增量与正常模式无显著差异。

**证据需求**：
- 在前 150 分钟消耗 70% 预算后，紧急模式在最后 30 分钟的得分 > 正常模式 × 1.15
- 紧急模式的 token 效率（分/token）> 正常模式 × 1.3

**消融维度**：
- C3a: 时间紧急模式（降级模型 + 最大并发 + 只做高信心题）
- C3b: 预算紧急模式（降级模型 + 减少并发 + 只做高边际收益题）
- C3c: 双重紧急（C3a + C3b 联动）

### Claim 4: 态势感知的自身开销 < 解题预算的 5%

**可证伪条件**：态势感知（信心估计、边际收益计算、状态更新）的 token 消耗 > 总预算的 5%。

**证据需求**：
- 态势评估每 5 步触发一次，每次消耗 < 200 tokens
- 全程态势感知总消耗 < 总预算的 3%

---

## 4. Architecture Design

### 4.1 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                      Race Intelligence Engine                │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Micro       │  │  Meso        │  │  Macro              │ │
│  │  Awareness   │  │  Awareness   │  │  Awareness          │ │
│  │              │  │              │  │                     │ │
│  │  C_i(t) =    │  │  S(t) =      │  │  MV_i(t) =          │ │
│  │  α·H + β·P   │  │  {solved,    │  │  s_i · p̂_i / t̂_i   │ │
│  │  + γ·D       │  │   active,    │  │                     │ │
│  │              │  │   budget,    │  │  MAB: UCB1-Tuned    │ │
│  │  每5步更新   │  │   time}      │  │  最优停止: 37%规则  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬──────────┘ │
│         │                 │                      │            │
│         └─────────────────┼──────────────────────┘            │
│                           │                                   │
│                    ┌──────▼───────┐                           │
│                    │  Decision    │                           │
│                    │  Engine      │                           │
│                    │              │                           │
│                    │  三态决策:   │                           │
│                    │  · 正常态    │                           │
│                    │  · 时间紧急  │                           │
│                    │  · 预算紧急  │                           │
│                    └──────┬───────┘                           │
│                           │                                   │
│              ┌────────────┼────────────┐                      │
│              │            │            │                      │
│        ┌─────▼────┐ ┌────▼─────┐ ┌────▼─────┐               │
│        │ Model    │ │ Concur-  │ │ Per-Q    │               │
│        │ Selector │ │ rency    │ │ Budget   │               │
│        │          │ │ Adjuster │ │ Adjuster │               │
│        └──────────┘ └──────────┘ └──────────┘               │
└──────────────────────────────────────────────────────────────┘
         │                    │                │
         ▼                    ▼                ▼
┌──────────────────────────────────────────────────────┐
│              Existing CTF-Agent Infrastructure        │
│                                                      │
│  race_strategy.py  budget.py  main_agent.py          │
│  (改造)            (改造)     (集成)                  │
└──────────────────────────────────────────────────────┘
```

### 4.2 决策引擎：三态决策规则

```python
@dataclass
class RaceState:
    """竞赛全局状态"""
    time_remaining: float       # 分钟
    budget_remaining: float     # tokens
    budget_rate: float          # tokens/min
    solved_count: int
    total_count: int
    active_questions: list      # 正在求解的题目
    pending_questions: list     # 未开始的题目
    question_states: dict       # qid -> QuestionState

@dataclass
class QuestionState:
    """单题状态"""
    qid: str
    score: int
    category: str
    confidence: float           # C_i(t)
    marginal_value: float       # MV_i(t)
    budget_consumed: float
    time_consumed: float
    steps_taken: int
    error_history: list

class DecisionEngine:
    """三态决策引擎"""

    # 状态阈值
    TIME_TIGHT = 30.0           # 分钟
    BUDGET_TIGHT_RATIO = 0.25   # 剩余预算 < 25%
    CONFIDENCE_LOW = 0.3
    MV_THRESHOLD_PERCENTILE = 0.3  # 只做 MV 前 30% 的题

    def decide(self, state: RaceState) -> Allocation:
        """主决策函数"""

        # 判断当前状态
        regime = self._classify_regime(state)

        if regime == "NORMAL":
            return self._normal_allocation(state)
        elif regime == "TIME_TIGHT":
            return self._time_tight_allocation(state)
        elif regime == "BUDGET_TIGHT":
            return self._budget_tight_allocation(state)
        else:  # BOTH_TIGHT
            return self._emergency_allocation(state)

    def _classify_regime(self, state: RaceState) -> str:
        """状态分类"""
        time_tight = state.time_remaining < self.TIME_TIGHT
        rpi = (state.budget_rate * state.time_remaining
               / max(state.budget_remaining, 1))
        budget_tight = rpi > 1.0 or \
            state.budget_remaining / state.budget_total < self.BUDGET_TIGHT_RATIO

        if time_tight and budget_tight:
            return "BOTH_TIGHT"
        elif time_tight:
            return "TIME_TIGHT"
        elif budget_tight:
            return "BUDGET_TIGHT"
        else:
            return "NORMAL"

    def _normal_allocation(self, state: RaceState) -> Allocation:
        """正常态：平衡攻难与扫易"""
        # 按边际收益排序所有活跃+待选题目
        all_q = state.active_questions + state.pending_questions
        ranked = sorted(all_q, key=lambda q: q.marginal_value, reverse=True)

        # 动态并发：基于剩余时间调整
        concurrency = self._optimal_concurrency(state)

        # 模型选择：按题目难度分配
        model_map = {}
        for q in ranked:
            if q.category in ("crypto", "pwn", "reverse"):
                model_map[q.qid] = "heavy"
            elif q.category in ("web", "misc"):
                model_map[q.qid] = "light"
            else:
                model_map[q.qid] = "tiny"

        return Allocation(
            model_map=model_map,
            concurrency=concurrency,
            focus=ranked[:concurrency],
            per_question_budget=state.budget_remaining / len(ranked) * 1.5
        )

    def _time_tight_allocation(self, state: RaceState) -> Allocation:
        """时间紧急态：最大并发 + 只做高信心题"""
        # 只保留信心 > 阈值的题目
        viable = [q for q in state.active_questions
                  if q.confidence > self.CONFIDENCE_LOW]
        viable += [q for q in state.pending_questions
                   if q.marginal_value > self._mv_threshold(state)]

        # 全部降级到轻量模型
        model_map = {q.qid: "light" for q in viable}

        # 最大并发抢时间
        return Allocation(
            model_map=model_map,
            concurrency=min(len(viable), 8),  # 最大并发 8
            focus=sorted(viable,
                         key=lambda q: q.marginal_value,
                         reverse=True)[:8],
            per_question_budget=state.budget_remaining / max(len(viable), 1)
        )

    def _budget_tight_allocation(self, state: RaceState) -> Allocation:
        """预算紧急态：降级模型 + 减少并发 + 只做高 MV 题"""
        # 只保留边际收益前 30% 的题目
        all_q = state.active_questions + state.pending_questions
        ranked = sorted(all_q, key=lambda q: q.marginal_value, reverse=True)
        cutoff = max(1, int(len(ranked) * self.MV_THRESHOLD_PERCENTILE))
        focus = ranked[:cutoff]

        # 降级到最便宜模型
        model_map = {q.qid: "tiny" for q in focus}

        # 减少并发以节省开销
        return Allocation(
            model_map=model_map,
            concurrency=max(1, min(3, len(focus))),
            focus=focus[:3],
            per_question_budget=state.budget_remaining / max(len(focus), 1) * 0.8
        )

    def _emergency_allocation(self, state: RaceState) -> Allocation:
        """双重紧急态：最小资源 + 最高收益题"""
        # 只做 1-2 道最高边际收益的题
        all_q = state.active_questions + state.pending_questions
        ranked = sorted(all_q, key=lambda q: q.marginal_value, reverse=True)
        focus = ranked[:2]

        model_map = {q.qid: "tiny" for q in focus}

        return Allocation(
            model_map=model_map,
            concurrency=1,  # 单线程集中火力
            focus=focus,
            per_question_budget=state.budget_remaining / 2
        )

    def _optimal_concurrency(self, state: RaceState) -> int:
        """基于资源压力指数的最优并发数"""
        rpi = (state.budget_rate * state.time_remaining
               / max(state.budget_remaining, 1))
        if rpi < 0.3:
            return 8  # 资源充裕，最大并发
        elif rpi < 0.6:
            return 6
        elif rpi < 0.8:
            return 4
        else:
            return 2  # 资源紧张，降低并发

    def _mv_threshold(self, state: RaceState) -> float:
        """边际收益阈值（第 30 百分位）"""
        all_q = state.active_questions + state.pending_questions
        mvs = sorted([q.marginal_value for q in all_q])
        idx = int(len(mvs) * self.MV_THRESHOLD_PERCENTILE)
        return mvs[idx] if mvs else 0.0
```

### 4.3 信心估计器

```python
class ConfidenceEstimator:
    """微观态势：单题信心估计"""

    def __init__(self, k: int = 5, alpha=0.4, beta=0.35, gamma=0.25):
        self.k = k
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

    def estimate(self, qid: str, step_history: list,
                 error_history: list, budget_ratio: float) -> float:
        """
        C_i(t) = α·H_i(t) + β·P_i(t) + γ·D_i(t)

        Args:
            qid: 题目 ID
            step_history: 最近 k 步的工具输出
            error_history: 最近 k 步的错误分类
            budget_ratio: 已消耗预算 / 单题预算
        """
        H = self._history_score(step_history)
        P = self._pattern_score(error_history)
        D = self._difficulty_score(budget_ratio)

        return self.alpha * H + self.beta * P + self.gamma * D

    def _history_score(self, step_history: list) -> float:
        """最近 k 步中新线索的比例"""
        if not step_history:
            return 0.5  # 无历史时返回中性值

        recent = step_history[-self.k:]
        new_clues = sum(1 for step in recent
                        if self._has_new_clue(step))
        return new_clues / len(recent)

    def _has_new_clue(self, step_output: str) -> bool:
        """判断步骤输出是否包含新线索"""
        # 启发式：输出中是否包含新的 URL/函数名/地址/flag 片段
        import re
        patterns = [
            r'https?://[^\s]+',        # URL
            r'0x[0-9a-fA-F]+',         # 内存地址
            r'flag\{[^\}]*\}',         # flag
            r'[a-zA-Z_]\w*\(',         # 函数调用
        ]
        for p in patterns:
            if re.search(p, step_output):
                return True
        return False

    def _pattern_score(self, error_history: list) -> float:
        """基于错误分类历史的模式匹配分数"""
        if not error_history:
            return 0.5

        # 错误类别权重
        weights = {
            "continue": 0.8,        # 正常进展
            "redirect": 0.6,        # 方向调整
            "switch_strategy": 0.4, # 策略切换
            "stuck_loop": 0.1,      # 卡住
            "hallucination": 0.2,   # 幻觉
        }

        recent = error_history[-self.k:]
        scores = [weights.get(e, 0.5) for e in recent]
        return sum(scores) / len(scores)

    def _difficulty_score(self, budget_ratio: float) -> float:
        """基于资源消耗的难度估计（指数衰减）"""
        import math
        return math.exp(-2.0 * budget_ratio)
```

### 4.4 边际收益估计器（MAB 集成）

```python
import math

class MarginalValueEstimator:
    """宏观态势：边际收益估计 + MAB 探索"""

    def __init__(self, exploration_factor: float = 1.0):
        self.exploration_factor = exploration_factor
        self.pull_counts = {}       # qid -> 拉臂次数
        self.total_pulls = 0

    def estimate(self, qid: str, score: int, confidence: float,
                 avg_time: float, time_pulled: float) -> float:
        """
        MV_i(t) = s_i · p̂_i / t̂_i + UCB 探索项

        结合 UCB1-Tuned 的探索-利用平衡：
        - 利用项：s_i · p̂_i / t̂_i（边际收益）
        - 探索项：sqrt(2·ln(N) / n_i)（鼓励尝试未探索的题）
        """
        # 利用项
        p_hat = confidence  # 估计解出概率
        t_hat = max(avg_time * (1 - confidence), 1.0)  # 估计剩余时间
        exploit = score * p_hat / t_hat

        # 探索项（UCB1 变体）
        n_i = self.pull_counts.get(qid, 0)
        N = self.total_pulls
        if n_i == 0:
            explore = float('inf')  # 未探索的题优先
        else:
            explore = math.sqrt(2 * math.log(N + 1) / n_i)

        return exploit + self.exploration_factor * explore

    def record_pull(self, qid: str):
        """记录一次拉臂"""
        self.pull_counts[qid] = self.pull_counts.get(qid, 0) + 1
        self.total_pulls += 1
```

---

## 5. Differentiation（竞品矩阵）

### 5.1 五维度对比

| 维度 | hydra | LLM-CTF-Solver | CoRedteam | verialabs | SageCTF | **本方案** |
|------|-------|-----------------|-----------|-----------|---------|-----------|
| **态势感知** | ❌ 无 | ❌ 无 | ❌ 无 | ❌ 无 | ⚠️ 静态 | ✅ **三维实时** |
| **资源分配** | 固定 cost-cap | 双熔断 | 迭代预算 | ❌ 无 | 固定拓扑 | ✅ **动态三态** |
| **换题策略** | 超时换题 | 六维僵局 | — | — | — | ✅ **边际收益驱动** |
| **理论基础** | 经验规则 | 经验规则 | 经验规则 | 经验规则 | 经验规则 | ✅ **MAB + 最优停止** |
| **竞赛适配** | 通用 | BUUCTF | Web | BSidesSF | DEF CON | ✅ **西湖论剑** |

### 5.2 关键差异化点

1. **vs hydra（华沙大学）**：
   - hydra 的 cost-cap 是"一刀切"：超限就停。本方案是"精打细算"：根据边际收益动态分配。
   - hydra 的 triage 是静态分流（开赛分类）。本方案的态势感知是动态的：中途发现某题比预期难，立即调整优先级。

2. **vs LLM-CTF-Solver**：
   - LLM-CTF-Solver 的六维僵局检测只关注"是否卡住"。本方案关注"卡住了值不值得继续"——通过边际收益判断。
   - LLM-CTF-Solver 无并发、无预算分层。本方案是完整的资源管理系统。

3. **vs CoRedteam（微软）**：
   - CoRedteam 的 Consolidator 是赛后/预算耗尽后触发。本方案的态势感知是赛中实时的。
   - CoRedteam 仅覆盖 Web 题。本方案全题型覆盖。

4. **vs verialabs（BSidesSF 冠军）**：
   - verialabs 的 swarm 是"暴力并发"：所有题同时跑。本方案是"智能并发"：根据边际收益分配资源。
   - verialabs 无预算管控。本方案有三级熔断。

5. **vs SageCTF（DEF CON 前 5%）**：
   - SageCTF 的自生成拓扑在开赛后不再变化。本方案的分配策略每 5 步重新评估。
   - SageCTF 依赖重型模型。本方案通过动态降级在预算约束下工作。

---

## 6. Experiment Plan

### 6.1 实验环境

| 项目 | 配置 |
|------|------|
| 题目集 | 西湖论剑 40+ 道真题（含 Web/Crypto/Misc/Pwn/Reverse） |
| 模型 | DeepSeek-V3 (heavy) / DeepSeek-V2-Lite (light) / Qwen2.5-7B (tiny) |
| 总预算 | 500K tokens/轮 |
| 总时间 | 模拟 180 分钟（实际可压缩） |
| 重复次数 | 10 轮（固定 seed 0-9） |
| 统计检验 | 双侧配对 $t$ 检验，$\alpha = 0.05$，功效 $1-\beta = 0.8$ |

### 6.2 消融矩阵

| 实验 ID | 配置 | 目的 |
|---------|------|------|
| **E0** | 静态分配（当前 baseline） | 基准线 |
| **E1a** | E0 + 微观态势（单题信心换题） | 信心估计的单独贡献 |
| **E1b** | E0 + 中观态势（资源压力感知） | 全局感知的单独贡献 |
| **E1c** | E0 + 宏观态势（边际收益排序） | 边际收益的单独贡献 |
| **E1d** | E0 + 三层联动（完整方案） | 完整方案效果 |
| **E2a** | E1d - MAB 探索项 | MAB 探索的价值 |
| **E2b** | E1d - 紧急模式 | 紧急模式的价值 |
| **E2c** | E1d - 动态并发（固定并发=4） | 动态并发的价值 |
| **E3a** | E1d，预算减半（250K tokens） | 预算压力下的鲁棒性 |
| **E3b** | E1d，时间减半（90 分钟） | 时间压力下的鲁棒性 |

### 6.3 评估指标

| 指标 | 定义 | 目标 |
|------|------|------|
| **解出数** | 成功提交 flag 的题目数 | +20% vs E0 |
| **总分** | 解出题目的分值之和 | +20% vs E0 |
| **Token 效率** | 总分 / 总 token 消耗 | +15% vs E0 |
| **时间效率** | 总分 / 总时间消耗 | +15% vs E0 |
| **浪费率** | 投入"注定失败"题目的 token / 总 token | -30% vs E0 |
| **态势感知开销** | 态势评估的 token 消耗 / 总 token | < 5% |

### 6.4 统计功效分析

假设效应量 $d = 0.5$（中等效应），显著性水平 $\alpha = 0.05$（双侧），功效 $1-\beta = 0.8$：

$$n = \left(\frac{z_{1-\alpha/2} + z_{1-\beta}}{d}\right)^2 = \left(\frac{1.96 + 0.84}{0.5}\right)^2 \approx 31.4$$

因此需要至少 **32 轮**重复实验。考虑到每轮实验耗时约 30 分钟（压缩模式），总实验时间约 16 小时。

**实际操作**：先用 10 轮做初步验证（功效约 0.6），若效应量足够大（$d > 0.8$）则 10 轮已足够；若效应量不显著，再增加到 32 轮。

### 6.5 实验控制

| 控制项 | 措施 |
|--------|------|
| **随机性** | 固定 seed（0-9），确保 LLM 输出可复现 |
| **题目顺序** | 所有实验使用相同的题目呈现顺序 |
| **模型版本** | 锁定 API 版本，避免模型更新影响结果 |
| **网络延迟** | 记录 API 延迟，排除异常值 |
| **并发公平性** | 所有配置使用相同的最大并发上限（8） |

---

## 7. Implementation Plan（日粒度）

### Phase 1: 核心引擎（Day 1-3）

| Day | Task | 产出 | Priority |
|-----|------|------|----------|
| **D1** | 实现 `ConfidenceEstimator` 类 | `core/confidence.py` | P0 |
| **D1** | 实现 `MarginalValueEstimator` 类 | `core/marginal_value.py` | P0 |
| **D2** | 实现 `DecisionEngine` 三态决策 | `core/decision_engine.py` | P0 |
| **D2** | 实现 `RaceState` 状态收集器 | `core/race_state.py` | P0 |
| **D3** | 集成态势感知循环到 `main_agent.py` | 改造 `core/main_agent.py` | P0 |
| **D3** | 改造 `race_strategy.py` 支持动态排序 | 改造 `core/race_strategy.py` | P0 |

### Phase 2: 调度集成（Day 4-5）

| Day | Task | 产出 | Priority |
|-----|------|------|----------|
| **D4** | 改造 `budget.py` 支持动态分配 | 改造 `scheduler/budget.py` | P0 |
| **D4** | 实现模型等级切换逻辑 | `scheduler/model_router.py` | P0 |
| **D5** | 实现动态并发调整 | 改造 `scheduler/` | P1 |
| **D5** | 实现紧急模式触发逻辑 | `core/emergency.py` | P1 |

### Phase 3: 看板与观测（Day 6-7）

| Day | Task | 产出 | Priority |
|-----|------|------|----------|
| **D6** | 态势感知指标暴露到 Dashboard | 改造看板 | P1 |
| **D6** | 实时展示：信心分数、边际收益、三态状态 | 看板新增面板 | P1 |
| **D7** | 决策日志记录（每次分配决策的原因） | `logs/decision_log.jsonl` | P2 |

### Phase 4: 实验与调优（Day 8-10）

| Day | Task | 产出 | Priority |
|-----|------|------|----------|
| **D8** | 消融实验 E0-E1d（10 轮） | `experiments/ablation_phase1.csv` | P0 |
| **D9** | 消融实验 E2a-E2c（10 轮） | `experiments/ablation_phase2.csv` | P0 |
| **D10** | 消融实验 E3a-E3b（10 轮） + 统计分析 | `experiments/results_final.md` | P0 |

### 与现有代码的改造点清单

| 文件 | 改造内容 | 改动量 |
|------|----------|--------|
| `core/race_strategy.py` | 新增 `RaceState` 数据类；`plan_challenges()` 改为调用 `DecisionEngine`；新增 `update_state()` 方法 | 中（~80 行新增，~30 行改造） |
| `scheduler/budget.py` | `BudgetTracker.check()` 接受动态预算参数；新增 `adjust_budget()` 方法支持按题分配；`check()` 返回值增加 `BUDGET_EMERGENCY` 状态 | 中（~50 行新增，~20 行改造） |
| `core/main_agent.py` | `solve()` 方法中每 5 步调用态势评估；`AgentContext` 新增 `confidence`、`marginal_value` 字段；`_finalize()` 输出增加态势指标 | 大（~100 行新增，~40 行改造） |
| `scheduler/` (新增) | 新增 `model_router.py` 实现模型等级切换 | 新增（~60 行） |
| `core/` (新增) | 新增 `confidence.py`、`marginal_value.py`、`decision_engine.py`、`race_state.py`、`emergency.py` | 新增（~400 行） |

---

## 8. 方法论注意事项（已知坑及规避）

### 8.1 并发 vs 预算语义一致性

**坑**：并发调整时，单题预算的语义会变化。例如，并发从 4 降到 2 时，每题可分配的预算翻倍，但如果预算分配逻辑没有同步调整，会导致某些题预算不足。

**规避**：
- `DecisionEngine` 统一管理并发数和预算分配，确保联动
- `per_question_budget = budget_remaining / concurrency`，始终基于当前并发数计算
- 在 `Allocation` 中同时返回 `concurrency` 和 `per_question_budget`，避免不一致

### 8.2 态势评估自身成本

**坑**：态势感知本身消耗 token（需要 LLM 评估信心），如果频率过高，可能消耗 > 5% 的预算。

**规避**：
- 信心估计使用**纯规则**（不调用 LLM），成本为 0
- 边际收益计算使用**纯数学公式**，成本为 0
- 仅在"是否换题"的决策点使用轻量 LLM 辅助判断（可选）
- 记录态势评估的耗时，确保 < 100ms/次

### 8.3 实验统计功效

**坑**：10 轮重复实验的功效可能不足（$1-\beta \approx 0.6$），无法检测到中等效应量。

**规避**：
- 先用 10 轮做初步验证，若效应量 $d > 0.8$ 则已足够
- 若 $d$ 在 0.5-0.8 之间，增加到 32 轮
- 使用配对 $t$ 检验（而非独立 $t$ 检验），提高统计功效
- 报告效应量和置信区间，而非仅报告 $p$ 值

### 8.4 信心估计的冷启动

**坑**：比赛开始时，所有题目的信心分数都是中性值（0.5），无法有效区分优先级。

**规避**：
- 使用**先验知识**：基于题目类别和附件大小的初始排序（现有 `difficulty_score()`）
- 前 10 分钟为"探索期"：每道题尝试 2-3 步，快速建立初始信心
- 探索期结束后进入"利用期"：按边际收益排序

### 8.5 LLM 输出随机性对实验复现性的影响

**坑**：即使固定 seed，不同 API 调用的输出也可能不同（温度 > 0、网络延迟差异）。

**规避**：
- 设置 `temperature = 0` 确保确定性输出
- 记录每次 LLM 调用的输入/输出到日志，支持事后复现
- 若 API 不支持 temperature=0，使用 mock 响应做消融实验

---

## 9. 理论附录：MAB 与最优停止

### 9.1 Multi-Armed Bandit 形式化

将 CTF 竞赛建模为**带成本的有限时间 MAB 问题**：

- **臂集合**：$K = \{q_1, q_2, \ldots, q_n\}$，每道题是一个臂
- **拉臂收益**：$r_i = s_i \cdot \mathbb{1}[\text{solved}(q_i)]$，解出得分，否则 0
- **拉臂成本**：$c_i = t_i$，消耗时间
- **时间预算**：$T = 180$ 分钟
- **目标**：在 $\sum c_i \leq T$ 约束下最大化 $\sum r_i$

标准 MAB 问题（无成本约束）的 UCB1 算法选择：

$$a^* = \arg\max_i \left[ \hat{\mu}_i + \sqrt{\frac{2 \ln N}{n_i}} \right]$$

带成本的变体 UCB1-Tuned 选择：

$$a^* = \arg\max_i \left[ \frac{\hat{\mu}_i}{c_i} + \sqrt{\frac{2 \ln N}{n_i}} \right]$$

其中 $\hat{\mu}_i / c_i$ 正是**边际收益** $\text{MV}_i$。

### 9.2 最优停止理论

在 $n$ 道题中依次选择，经典 Secretary Problem 的最优策略：
1. 观察前 $r^* = \lfloor n/e \rfloor$ 道题，记录最大收益
2. 之后选择第一个超过观察期最大值的题

在 CTF 场景中的映射：
- **观察期**（前 40 分钟）：每道题尝试 2-3 步，估计 $p_i$ 和 $t_i$
- **选择期**（后 140 分钟）：只做 $\text{MV}_i$ 超过阈值的题
- **阈值更新**：随着更多信息积累，动态调整阈值

这比固定阈值的 Secretary Problem 更优，因为我们可以在选择期继续更新估计。

---

## 10. 参考文献

1. Auer, P., Cesa-Bianchi, N., & Fischer, P. (2002). Finite-time analysis of the multiarmed bandit problem. *Machine Learning*, 47(2-3), 235-256.
2. Ferguson, T. S. (1989). Who solved the secretary problem? *Statistical Science*, 4(3), 282-289.
3. hydra — 华沙大学批量求解框架，cost-cap 实现（2025）
4. LLM-CTF-Solver — 六维僵局检测 + 双熔断（2024）
5. CoRedteam — 微软 Consolidator 永久记忆（2025）
6. SageCTF — DEF CON 前 5%，自生成拓扑（2026）
7. verialabs/ctf-agent — BSidesSF 冠军，swarm 并发（2024）
8. 本项目 `core/race_strategy.py` — 先易后难基础
9. 本项目 `scheduler/budget.py` — 三级熔断基础
10. 本项目 `core/main_agent.py` — Plan-Act-Observe 循环基础
