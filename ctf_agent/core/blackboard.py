"""事实黑板（2026-09-02）：跨会话共享状态——presolve 确定性结果缓存复用。

借鉴 SecAutoMind「事实黑板」思路（Agent 间通过共享黑板传递上下文），
本项目落地为 data/results/blackboard.json（gitignored 本地文件，跨会话/跨进程共享）：
1. presolve 对同一真题重复计算（benchmark / 真实验证 / 多会话并行）→ 黑板缓存命中直接复用，
   跳过重算——挂钩解题速度（同题二次命中毫秒级返回）。
2. 记录 known_failures（失败分类）——供复盘报告（P0MA-CX）与失败桶统计。

接口（线程安全）：
    Blackboard().get_presolve(task_id) -> flag|None      # 查缓存
    Blackboard().set_presolve(task_id, flag, source)      # 写缓存（成功后）
    Blackboard().record_failure(task_id, category, reason)# 记失败（供复盘）
    Blackboard().get_failures(category=None) -> list      # 查失败记录
"""

import json
import os
import threading
import time

_BLACKBOARD_PATH = os.path.join("data", "results", "blackboard.json")
_lock = threading.Lock()


class Blackboard:
    """事实黑板：JSON 持久化 + 线程安全读写。"""

    def __init__(self, path: str = _BLACKBOARD_PATH) -> None:
        self.path = path
        self._data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
                if isinstance(d, dict):
                    return d
        except (OSError, json.JSONDecodeError):
            pass
        return {"presolve_cache": {}, "known_failures": {}}

    def save(self) -> None:
        with _lock:
            tmp = f"{self.path}.tmp"
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._data, f, ensure_ascii=False, indent=1)
                os.replace(tmp, self.path)
            except OSError:
                pass  # 黑板写失败不阻塞主流程（只读复用优先）

    # ── presolve 缓存（跨会话复用核心）──────────────────────────
    def get_presolve(self, task_id: str):
        """查 presolve 缓存：返回 (flag, source, ts) 或 None。"""
        entry = self._data.get("presolve_cache", {}).get(str(task_id))
        if not entry:
            return None
        return entry.get("flag"), entry.get("source"), entry.get("ts")

    def set_presolve(self, task_id: str, flag: str, source: str = "presolve") -> None:
        """写 presolve 缓存（解出成功后调用）。"""
        if not flag:
            return
        self._data.setdefault("presolve_cache", {})[str(task_id)] = {
            "flag": str(flag),
            "source": source,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.save()

    # ── 失败记录（供复盘报告 / 失败桶）──────────────────────────
    def record_failure(self, task_id: str, category: str, reason: str = "") -> None:
        self._data.setdefault("known_failures", {}).setdefault(str(task_id), []).append({
            "category": category,
            "reason": str(reason)[:200],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        self.save()

    def get_failures(self, category: str | None = None) -> list:
        out = []
        for tid, recs in self._data.get("known_failures", {}).items():
            for r in recs:
                if category is None or r.get("category") == category:
                    out.append({"task_id": tid, **r})
        return out


# 模块级单例（避免每次重复读盘）
_blackboard = None


def get_blackboard() -> Blackboard:
    global _blackboard
    if _blackboard is None:
        _blackboard = Blackboard()
    return _blackboard
