"""决赛 e2e 平台验证（Backlog B-04）：list → get_challenge → 附件/靶机 → 数据齐全检查。

用途：决赛前 1h 与赛前必跑，验证"真实平台链路"端到端可用——
  list_challenges 通 → 每题 get_challenge 题面非空 → has_attachment 的题附件 URL 可达
  → 有 endpoints 的题靶机地址解析成功。
退出码：0 = 全部通过；1 = 存在失败（打印明细）；2 = 平台未配置/不可达。

用法：
  .venv/Scripts/python.exe scripts/_e2e_verify.py            # 默认：每类抽样 ≤3 题
  .venv/Scripts/python.exe scripts/_e2e_verify.py --all      # 全部题逐一检查
  .venv/Scripts/python.exe scripts/_e2e_verify.py --deep     # 附件真实下载前 2 个（慢，慎用）
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

from ctfplatform.dasctf import DasCTFPlatform


async def _head_ok(url: str, token: str = "", timeout: float = 15.0) -> bool:
    """HEAD 检查附件 URL 可达性（不下载内容，大文件安全）。"""
    headers = {}
    if token:
        headers["Authorization"] = token
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, trust_env=False) as c:
            r = await c.head(url, headers=headers)
            return r.status_code in (200, 204)
    except Exception:
        # 部分 CDN 拒绝 HEAD，降级为 GET Range 探测 1 字节
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, trust_env=False) as c:
                r = await c.get(url, headers={**headers, "Range": "bytes=0-0"})
                return r.status_code in (200, 206)
        except Exception:
            return False


async def main() -> int:
    p = DasCTFPlatform()
    if not p.base_url:
        print("FAIL: 未配置平台地址（DASCTF_BASE_URL / CTF_AGENT_PLATFORM_BASE_URL）")
        return 2
    deep = "--deep" in sys.argv
    all_ = "--all" in sys.argv
    print(f"=== 平台 e2e 验证 (B-04, deep={deep}, all={all_}) ===")

    # 1. list_challenges
    try:
        challenges = await p.list_challenges()
    except Exception as e:  # noqa: BLE001
        print(f"FAIL list_challenges: {e}")
        return 1
    print(f"list_challenges OK: {len(challenges)} 题")
    if not challenges:
        print("WARN: 平台无题（可能未开放），e2e 中止（决赛前 1h 再跑）")
        return 0

    # 2. 抽样：每类 ≤3 题（--all 全查）
    from collections import defaultdict

    by_cat = defaultdict(list)
    for ch in challenges:
        by_cat[str(ch.category or "misc")].append(ch)
    sample: list = []
    for cat, lst in sorted(by_cat.items()):
        sample.extend(lst if all_ else lst[:3])

    fails: list[tuple] = []
    checked = 0
    for ch in sample:
        checked += 1
        cid = str(ch.id)
        try:
            detail = await p.get_challenge(cid)
        except Exception as e:  # noqa: BLE001
            fails.append((cid, ch.title, f"get_challenge EXC: {e}"))
            continue
        if detail is None:
            fails.append((cid, ch.title, "get_challenge 返回 None"))
            continue
        ex = detail.extra or {}
        desc = str(detail.description or "")
        problems = []
        if not desc.strip():
            problems.append("题面为空")
        if getattr(detail, "has_attachment", False):
            try:
                urls = await p.download_attachment(cid)
            except Exception as e:  # noqa: BLE001
                problems.append(f"download_attachment EXC: {e}")
                urls = []
            if not urls:
                problems.append("has_attachment 但无附件 URL")
            else:
                if deep:
                    got = 0
                    for u in urls[:2]:
                        try:
                            b = await p.download_attachment_bytes(u)
                            if b:
                                got += 1
                        except Exception as e:  # noqa: BLE001
                            problems.append(f"附件下载失败 {u}: {e}")
                    if got == 0:
                        problems.append("附件真实下载全部失败")
                    else:
                        print(f"  ✓ {cid} 附件下载 {got}/{min(len(urls), 2)}")
                else:
                    ok_head = await _head_ok(urls[0], token=getattr(p, "token", ""))
                    if not ok_head:
                        problems.append(f"附件 URL 不可达: {urls[0]}")
                    else:
                        print(f"  ✓ {cid} 附件 URL 可达 ({urls[0][:80]})")
        eps = ex.get("endpoints") or []
        if eps:
            try:
                from scripts._scan_firstblood import _extract_targets

                tg = _extract_targets(ex)
                if not tg:
                    problems.append("有 endpoints 但解析不出靶机地址")
                else:
                    print(f"  ✓ {cid} 靶机解析 {tg[:2]}")
            except Exception as e:  # noqa: BLE001
                problems.append(f"靶机解析 EXC: {e}")
        if problems:
            fails.append((cid, ch.title, "; ".join(problems)))
        else:
            print(f"  ✓ {cid} 数据齐全 [{ch.category}] {ch.title[:30]}")

    print(f"\n检查 {checked} 题：")
    if fails:
        print(f"❌ {len(fails)} 题有问题：")
        for cid, title, prob in fails:
            print(f"  - {cid} {title}: {prob}")
        return 1
    print("🎉 e2e 全部通过（题面/附件/靶机数据齐全）")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
