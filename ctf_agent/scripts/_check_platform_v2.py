"""全量平台状态检查：排名 + 全部题目（含新题）+ 公告 + 未解题详情。"""
import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctfplatform.dasctf import DasCTFPlatform


async def main():
    p = DasCTFPlatform()

    # 1. 排名
    ov = await p._request("GET", "overview")
    data = ov.get("data", ov) if ov else {}
    print(f"=== OVERVIEW ===")
    print(f"  排名: {data.get('stageRank')}  stagePoint: {data.get('stagePoint')}")

    # 2. 全部题目
    challenges = await p.list_challenges()
    print(f"\n=== 共 {len(challenges)} 题 ===")
    unsolved = []
    for ch in challenges:
        ex = ch.extra or {}
        solved = ex.get("hasSolved", False)
        score = ex.get("score", "?")
        diff = ex.get("difficulty", "?")
        marker = "✅" if solved else "❌"
        print(f"  {marker} [{ch.id}] {ch.title}  score={score}  diff={diff}")
        if not solved:
            unsolved.append(ch)

    # 3. 公告（可能发布新题通知）
    print("\n--- 公告列表 ---")
    try:
        notices = await p._request("GET", "notice_list")
        notice_data = notices.get("data", []) if notices else []
        items = []
        if isinstance(notice_data, list):
            items = notice_data
        elif isinstance(notice_data, dict):
            items = notice_data.get("records", notice_data.get("list", []))
        if items:
            for n in items[:10]:
                print(f"  [{n.get('id', '?')}] {n.get('title', '')} ({n.get('createTime', '')})")
        else:
            print(f"  (无公告或格式未知: {type(notice_data)})")
    except Exception as e:
        print(f"  公告拉取失败: {e}")

    # 4. 未解题详情
    if unsolved:
        print(f"\n=== 未解题详情 ({len(unsolved)}) ===")
        for ch in unsolved:
            detail = await p.get_challenge(ch.id)
            ex = detail.extra or {}
            print(f"\n--- {ch.id} {ch.title} ---")
            print(f"  description: {str(detail.description or '')[:300]}")
            print(f"  isNeedInit: {ex.get('isNeedInit')}")
            print(f"  isNeedCheck: {ex.get('isNeedCheck')}")
            # 附件
            attachments = ex.get("attachments", [])
            if attachments:
                print(f"  attachments ({len(attachments)}):")
                for att in attachments:
                    if isinstance(att, dict):
                        print(f"    - {att.get('name','?')} ({att.get('size','?')} bytes) url={str(att.get('url',''))[:100]}")
                    else:
                        print(f"    - {att}")
            # 靶机
            eps = ex.get("endpoints", [])
            for ep in eps:
                print(f"  endpoint: {json.dumps(ep, ensure_ascii=False)[:200]}")
            # 文件路径线索
            files = ex.get("files", ex.get("fileList", []))
            if files:
                print(f"  files: {json.dumps(files, ensure_ascii=False)[:300]}")
    else:
        print("\n🎉 全部题目已解出！检查是否有新题放出...")


asyncio.run(main())
