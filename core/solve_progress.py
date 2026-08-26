"""共享解题进度中心（postmortem high#1 落地）。

解决跨会话重复攻坚问题：多个并行会话共用一个状态文件，
任何会话攻克某题前先查 hasSolved 状态，避免对已解题绕远路。

用法：
    from core.solve_progress import SolveProgress
    sp = SolveProgress()
    sp.mark_solved("10662")          # 本会话解出后标记
    if sp.is_solved("10662"):        # 进题前查询
        skip
    sp.filter_unsolved(challenges)   # 过滤已解题列表
"""

import json
import os
import threading
import time

_PROGRESS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "results", "solve_progress.json",
)

_SESSION_ID = os.getenv("CTF_AGENT_SESSION_ID", "") or f"session-{os.getpid()}"


class SolveProgress:
    """跨会话共享的解题进度状态锁（文件级，带线程锁防并发写坏）。"""

    def __init__(self, path: str = "") -> None:
        self.path = path or _PROGRESS_PATH
        self._lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            self._write({"solved": {}, "updated_at": time.time(), "by": _SESSION_ID})

    def _read(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"solved": {}, "updated_at": time.time(), "by": _SESSION_ID}

    def _write(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)  # 原子替换，防并发读半截

    # ---- 查询 ----
    def is_solved(self, challenge_id: str) -> bool:
        """该题是否已被任何会话解出（本地状态锁 + 平台由调用方再确认）。"""
        with self._lock:
            data = self._read()
        return challenge_id in data.get("solved", {})

    def filter_unsolved(self, challenges: list) -> list:
        """过滤出尚未解出的题目（保留原始对象）。"""
        out = []
        for ch in challenges:
            cid = str(getattr(ch, "id", ch if isinstance(ch, str) else ""))
            # 平台 hasSolved 优先（权威）；其次本地状态锁
            platform_solved = bool(getattr(ch, "extra", None) and (ch.extra or {}).get("hasSolved"))
            if platform_solved or self.is_solved(cid):
                continue
            out.append(ch)
        return out

    # ---- 写入 ----
    def mark_solved(self, challenge_id: str, flag: str = "", note: str = "") -> None:
        """本会话解出后标记（含 flag 与时间，供其他会话跳过）。"""
        with self._lock:
            data = self._read()
            data.setdefault("solved", {})
            data["solved"][str(challenge_id)] = {
                "flag": flag,
                "note": note,
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "by": _SESSION_ID,
            }
            data["updated_at"] = time.time()
            self._write(data)

    # ---- 跨求解器解题发现共享（对标 verialabs message bus，防重复探索）----
    def record_attempt(self, challenge_id: str, path: str = "", result: str = "") -> None:
        """记录某会话对该题的尝试路径与结果（其他会话查到时跳过相同路径）。"""
        with self._lock:
            data = self._read()
            data.setdefault("attempts", {})
            data["attempts"].setdefault(str(challenge_id), [])
            # 避免重复记录完全相同的路径
            exist = [a for a in data["attempts"][str(challenge_id)]
                     if a.get("path") == path and a.get("by") == _SESSION_ID]
            if exist:
                return
            data["attempts"][str(challenge_id)].append({
                "path": path,
                "result": result,
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "by": _SESSION_ID,
            })
            data["updated_at"] = time.time()
            self._write(data)

    def get_attempts(self, challenge_id: str) -> list:
        """查询该题所有会话已尝试的路径（用于跳过重复探索）。"""
        with self._lock:
            data = self._read()
        return data.get("attempts", {}).get(str(challenge_id), [])

    def already_tried(self, challenge_id: str, path: str) -> bool:
        """该路径是否已被任何会话尝试过（多会话分工防重复）。"""
        attempts = self.get_attempts(challenge_id)
        return any(a.get("path") == path for a in attempts)

    # ---- 兼容旧 core.progress 接口（结构债合并：progress.py 将薄封装转发到这里）----
    def get_flag(self, challenge_id: str) -> str:
        """获取已解题目的 flag（用于跳过重复攻坚）。"""
        with self._lock:
            data = self._read()
        rec = data.get("solved", {}).get(str(challenge_id), {})
        return rec.get("flag", "") if rec else ""

    def solved_count(self) -> int:
        """已解题数。"""
        with self._lock:
            data = self._read()
        return len(data.get("solved", {}))

    def mark_attempted(self, challenge_id: str, title: str = "",
                       category: str = "") -> None:
        """标记题目已尝试（未解出，防止重复开始）——记录为尝试路径。"""
        self.record_attempt(challenge_id, path=title or "attempted",
                            result=f"attempted(cat={category})")

    def summary(self) -> dict:
        """汇总统计（兼容旧接口）。"""
        with self._lock:
            data = self._read()
        solved = data.get("solved", {})
        attempts = data.get("attempts", {})
        return {
            "solved_count": len(solved),
            "attempts_count": sum(len(v) for v in attempts.values()),
            "solved_ids": list(solved.keys()),
        }

    def snapshot(self) -> dict:
        with self._lock:
            return self._read()


# 模块级单例，方便 import 即用
_default = None


def get_progress() -> SolveProgress:
    global _default
    if _default is None:
        _default = SolveProgress()
    return _default
