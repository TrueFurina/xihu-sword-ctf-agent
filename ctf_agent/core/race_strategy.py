"""race_strategy：先易后难比赛策略调度（锐评「没有先易后难拿分策略」修复——2026-08-22）。

正式赛 0 解出锐评：埋头难题（CRYPTO-01 3 小时）——0 解出；最快队伍
先扫全部题——简单题 2 分钟秒解拿分。本模块把 docs/race_strategy.md
落地为代码：全量扫题 → 难度排序 → 单题限时 → 沉溺保护（超时换题+重访）。

用法：比赛入口/主循环拉题后调用 plan_challenges() 得执行队列；
每题开始前调用 should_stop_challenge() 检查限时；超时后入 revisit 队列。
"""

import time
from dataclasses import dataclass, field

# 单题限时（秒）——锐评 2 分钟/题标准
SIMPLE_TIMEOUT = 90      # 简单题（模板命中）——90s 目标
HARD_TIMEOUT = 300       # 难题攻坚硬上限——5 分钟（沉溺保护）
REVISIT_TIMEOUT = 180    # 重访题限时——3 分钟（第二梯队）

# 简单特征：小附件 + crypto/misc 优先
SIMPLE_CATEGORIES = {"crypto", "misc"}
SIMPLE_MAX_ATTACHMENT = 1_000_000  # 附件 < 1MB


def difficulty_score(challenge) -> int:
    """难度分（越小越先做）——先易后难排序依据。"""
    diff = str(getattr(challenge, "difficulty", "") or "").upper()
    cat = str(getattr(challenge, "category", "") or "").lower()
    attach_size = getattr(challenge, "attachment_size", 0) or 0
    score = {"EASY": 0, "MEDIUM": 1, "HARD": 2, "VERY_HARD": 3}.get(diff, 2) * 10
    if cat in SIMPLE_CATEGORIES:
        score -= 3  # crypto/misc 优先
    if attach_size and attach_size < SIMPLE_MAX_ATTACHMENT:
        score -= 2  # 小附件优先
    if getattr(challenge, "endpoints", None):
        score += 5  # 有靶机（web/pwn 交互）——后置
    return score


def plan_challenges(challenges: list) -> list:
    """全量扫题 → 难度排序 → 执行队列（先易后难）。"""
    return sorted(challenges, key=difficulty_score)


def challenge_timeout(challenge) -> int:
    """单题限时（秒）——简单题 90s/难题 300s/重访 180s。"""
    diff = str(getattr(challenge, "difficulty", "") or "").upper()
    cat = str(getattr(challenge, "category", "") or "").lower()
    if diff in ("EASY",) or (cat in SIMPLE_CATEGORIES and diff in ("EASY", "MEDIUM")):
        return SIMPLE_TIMEOUT
    return HARD_TIMEOUT


@dataclass
class RaceScheduler:
    """比赛调度器：执行队列 + 沉溺保护（超时换题 + 重访）。"""

    challenges: list = field(default_factory=list)
    queue: list = field(default_factory=list)      # 当前执行队列（先易后难）
    revisit: list = field(default_factory=list)    # 重访队列（超时换题的题）
    _started: dict = field(default_factory=dict)   # challenge_id -> 开始时间
    solved: set = field(default_factory=set)       # 已解出集合
    max_revisit: int = 2                            # 每题最多重访次数

    def __post_init__(self):
        self.queue = plan_challenges(self.challenges)

    def next_challenge(self):
        """取下一题（当前队列优先——空则重访队列）。"""
        if self.queue:
            c = self.queue.pop(0)
            self._started[id(c)] = time.monotonic()
            return c
        if self.revisit:
            c = self.revisit.pop(0)
            self._started[id(c)] = time.monotonic()
            return c
        return None

    def should_stop(self, challenge) -> bool:
        """限时检查——超时即 stop（沉溺保护）。"""
        sid = id(challenge)
        if sid not in self._started:
            self._started[sid] = time.monotonic()
        elapsed = time.monotonic() - self._started[sid]
        return elapsed >= challenge_timeout(challenge)

    def on_timeout(self, challenge) -> None:
        """超时处理——入重访队列（不放弃但后置）。"""
        sid = id(challenge)
        self._started.pop(sid, None)
        # 重访次数保护（防无限循环）
        n = getattr(challenge, "_revisit_count", 0)
        if n < self.max_revisit:
            challenge._revisit_count = n + 1
            self.revisit.append(challenge)

    def on_solved(self, challenge) -> None:
        """解出处理——记录 solved（唯一指标：解出数）。"""
        self.solved.add(getattr(challenge, "id", id(challenge)))
        self._started.pop(id(challenge), None)

    @property
    def progress(self) -> dict:
        """全局进度（唯一指标：解出数）。"""
        return {"solved": len(self.solved), "queue": len(self.queue),
                "revisit": len(self.revisit)}


if __name__ == "__main__":
    # 自测：难度排序（EASY 在前——crypto/misc 优先）
    from types import SimpleNamespace

    chs = [
        SimpleNamespace(id=3, title="REVERSE HARD", category="reverse", difficulty="HARD", attachment_size=900_000),
        SimpleNamespace(id=1, title="crypto EASY", category="crypto", difficulty="EASY", attachment_size=5_000),
        SimpleNamespace(id=2, title="misc MEDIUM", category="misc", difficulty="MEDIUM", attachment_size=20_000),
    ]
    plan = plan_challenges(chs)
    print("排序:", [c.id for c in plan])  # 期望 [1, 2, 3]（crypto EASY → misc MEDIUM → REVERSE HARD）
    print("限时:", {c.id: challenge_timeout(c) for c in chs})  # 1→90s, 2→90s, 3→300s
