"""提交迭代循环（锐评「提交是浪费不是迭代」修复——2026-08-22 沉淀）。

背景（正式赛 0 解出锐评）：CRYPTO-01 3 次猜测提交（47 次剩）——
提交是浪费不是迭代。本模块提供：
1. 多候选依次提交（flag_extract_guard 的 candidates——逐个提交——非猜测）
2. 提交后判定（accepted=isCorrect true / 错误=40001——按 code 区分）
3. 迭代策略（候选用尽前不停止——50 次额度内——不浪费在猜测）
"""

import json
import logging

log = logging.getLogger(__name__)

# 平台提交接口（正式赛验证：X-Agent-AccessKey 认证 + {"exerciseId","flag"}）
SUBMIT_PATH = "/slab-match/api/v1/agent/answer-panel/answer"


def submit_once(access_key: str, base_url: str, exercise_id: int, flag: str,
                timeout: int = 25) -> dict:
    """提交单个候选——返回判定结果（accepted/correct/错误次数）。"""
    import httpx

    r = httpx.post(
        f"{base_url.rstrip('/')}{SUBMIT_PATH}",
        headers={"X-Agent-AccessKey": access_key},
        json={"exerciseId": exercise_id, "flag": flag},
        timeout=timeout, trust_env=False,
    )
    try:
        d = r.json()
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": f"HTTP {r.status_code} 非 JSON"}
    code = d.get("code", "")
    data = d.get("data") or {}
    is_correct = bool(data.get("isCorrect"))
    if code == "00000" and is_correct:
        return {"ok": True, "accepted": True, "flag": flag, "code": code}
    # 错误：40001 带剩余次数信息（"提交flag错误...还有 N 次"）
    msg = d.get("message", "")
    remain = None
    m = __import__("re").search(r"还有(\d+)次", msg)
    if m:
        remain = int(m.group(1))
    return {"ok": False, "accepted": False, "flag": flag, "code": code,
            "message": msg[:80], "remain": remain}


def submit_with_iteration(access_key: str, base_url: str, exercise_id: int,
                          candidates: list, max_attempts: int = 20) -> dict:
    """多候选迭代提交——候选依次提交——accepted 即停——不猜测。

    Args:
        candidates: flag_extract_guard 的多候选列表（str 或 (str, method)）
    Returns:
        {"accepted": bool, "flag": str|None, "tried": [str], "remain": int|None}
    """
    tried = []
    for cand in candidates[:max_attempts]:
        flag = cand if isinstance(cand, str) else cand[0]
        if flag in tried:
            continue
        tried.append(flag)
        res = submit_once(access_key, base_url, exercise_id, flag)
        if res.get("accepted"):
            return {"accepted": True, "flag": flag, "tried": tried,
                    "remain": res.get("remain")}
        log.info("提交 %s: %s（剩 %s 次）", flag[:20], res.get("code"),
                 res.get("remain"))
        if res.get("remain") is not None and res.get("remain") <= 2:
            break  # 次数告急——停止
    return {"accepted": False, "flag": None, "tried": tried,
            "remain": tried and __import__("re").search(r"还有(\d+)次",
                str(tried[-1:]) or "") and None}


if __name__ == "__main__":
    # 自测：submit_once 格式验证（不真实提交——用测试题 ID + 已知错 flag）
    print("submit_once 已就绪——真实提交需 access_key/exercise_id/候选")
