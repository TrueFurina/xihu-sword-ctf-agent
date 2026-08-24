"""抢一血快速扫描器：进场全遍历题目 → 难度/分数排序 → 识别最快可解题。

积分机制（手册确认）：递减积分，每解出一人扣 1%，最低 80% → 一血=100% 全分。
博弈本质：早解出 = 高分；一血 = 满分。正式赛 3h 窗口内，前几分钟的一血
价值远超后续稳定解题。

用法：
    python scripts/_scan_firstblood.py --probe        # 全遍历排序，只报告
    python scripts/_scan_firstblood.py --solve        # 全遍历 + 对最简单的 N 题走模板兜底
"""

import argparse
import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 同目录脚本复用（_race_start.py 的 RACE_PROFILES 单一事实源）
_SCRIPTS = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

# 难度权重：VERY_EASY 最快解，权重最高（最先尝试）
_DIFF_WEIGHT = {
    "VERY_EASY": 0,
    "EASY": 1,
    "MEDIUM": 2,
    "HARD": 3,
    "VERY_HARD": 4,
}
# 题型优先级：crypto/web 有确定性工具（crypto_auto/flag_scan）能秒解，优先抢；
# misc REAL 类题（大附件）慢且难，靠后（正式赛列表 difficulty/score 全 None，原排序退化列表序）
_CAT_PRIORITY = {"crypto": 0, "web": 1, "misc": 2, "reverse": 3, "pwn": 4}
# 分数权重：低分题通常更简单（50 分题 < 200 分题）
_SCORE_WEIGHT = 0.1


def _rank(ch) -> float:
    """排序键：越小越先抢。题型优先（crypto>web>misc）→ 难度 → 分数。

    难度缺失兜底（2026-08-22 锐评落地：正式赛列表 difficulty/score 全 None，
    原排序退化为列表序——「先易后难拿分」策略失效）：
    - difficulty 存在 → 直接用权重
    - difficulty 缺失但 score 存在 → 用分数推断简单度（≤50 分=VERY_EASY 优先）
    - 两者全缺失 → 按题型确定性工具覆盖度兜底（crypto/web 可秒解 → 优先）
    """
    extra = ch.extra or {}
    cat_w = _CAT_PRIORITY.get(str(getattr(ch, "category", "")).lower(), 2)
    diff = str(extra.get("difficulty", "")).upper()
    try:
        score = float(extra.get("score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    if diff in _DIFF_WEIGHT:
        diff_w = _DIFF_WEIGHT[diff]
    elif score > 0:
        # 难度缺失 → 低分题通常更简单，优先抢
        if score <= 50:
            diff_w = _DIFF_WEIGHT["VERY_EASY"]
        elif score <= 100:
            diff_w = _DIFF_WEIGHT["EASY"]
        elif score <= 200:
            diff_w = _DIFF_WEIGHT["MEDIUM"]
        else:
            diff_w = _DIFF_WEIGHT["HARD"]
    else:
        # 难度+分数全缺失 → 按题型确定性工具覆盖度兜底
        diff_w = _DIFF_WEIGHT["EASY"] if cat_w <= 1 else _DIFF_WEIGHT["MEDIUM"]
    # cat_w*10000 题型绝对优先，diff_w*100 难度次之，score*0.1 同级低分优先
    return cat_w * 10000 + diff_w * 100 + score * _SCORE_WEIGHT


async def scan(platform) -> list:
    """全遍历：拉题目列表（含 corpus 嵌套）→ 展平 → 排序 → 返回优先级队列。

    P0 修复（2026-08-21 正式赛）：列表接口 description/endpoints 缺失，
    逐题 get_challenge 补全详情（并发限 6），否则 _to_question 拿不到靶机地址，
    agent 只会纯推理空转。单题补全失败不阻塞（保持列表数据继续排）。
    """
    challenges = await platform.list_challenges()
    # 只保留未解出且开放的题
    open_unsolved = []
    for ch in challenges:
        extra = ch.extra or {}
        if extra.get("hasSolved"):
            continue
        open_unsolved.append(ch)

    # ── 详情补全（P0 修复）：并发 get_challenge 拉 endpoints/真实题面 ──
    import asyncio as _asyncio

    _sem = _asyncio.Semaphore(6)

    async def _enrich(ch):
        async with _sem:
            try:
                detail = await platform.get_challenge(str(ch.id))
                if detail is not None:
                    # P0 数据链路修复（2026-08-21）：详情 description 权威覆盖——
                    # 列表可能已把标题兜底进 ch.description（非空），"为空才填"会
                    # 让真实题面永远合并不进去（0 解出回归）。
                    _dd = getattr(detail, "description", "") or ""
                    if _dd and _dd != getattr(ch, "title", ""):
                        ch.description = _dd
                    _dextra = dict(getattr(detail, "extra", None) or {})
                    _cextra = dict(getattr(ch, "extra", None) or {})
                    for _k in ("endpoints", "attachment", "difficulty", "description",
                               "score", "flag_format"):
                        if _dextra.get(_k) is not None:
                            _cextra[_k] = _dextra[_k]
                    ch.extra = _cextra
                    # 附件判定（列表接口恒 False，附件在 extra.attachment.url）
                    _att = _cextra.get("attachment") or _cextra.get("attachments")
                    _has_att = bool(
                        getattr(detail, "has_attachment", False)
                        or (isinstance(_att, dict) and bool(_att.get("url")))
                        or (isinstance(_att, list) and bool(_att))
                    )
                    if _has_att:
                        ch.has_attachment = True
                    if getattr(detail, "has_instance", False):
                        ch.has_instance = True
            except Exception:  # noqa: BLE001 - 单题详情补全失败不阻塞排序
                pass
        return ch

    open_unsolved = await _asyncio.gather(*[_enrich(ch) for ch in open_unsolved])
    open_unsolved.sort(key=_rank)
    return open_unsolved


async def watch(platform, interval: float = 15.0, solve_top: int = 2) -> None:
    """公告轮询模式：定时拉题目+公告，新题开放瞬间自动触发抢一血。

    博弈点：正式赛题目可能分批开放（公告「新增赛题/已开放赛题」），
    新题开放的前几分钟是抢一血黄金窗口——本函数监控到新题立即扫描。
    """
    import time

    from core.solve_progress import get_progress
    from run import build_race_solver
    from _race_start import _race_profile

    sp = get_progress()
    seen_ids = set()
    solver = None
    print(f"=== 公告轮询抢一血模式（间隔 {interval}s，Ctrl+C 停止）===")
    while True:
        try:
            challenges = await platform.list_challenges()
            current_ids = {str(ch.id) for ch in challenges}
            # 发现新题（之前未见）→ 触发抢一血
            new_ids = current_ids - seen_ids
            if new_ids:
                for nid in new_ids:
                    print(f"🎯 检测到新题开放: {nid}！立即抢一血扫描")
                seen_ids = current_ids
                ranked = await scan(platform)
                if not ranked:
                    print("  新题已解出或未开放，继续监控")
                else:
                    if solver is None:
                        from run import build_platform_solver
                        _race = build_race_solver(use_mock=False, **_race_profile())
                        # B-23 修复（2026-08-21 决赛备战）：复用 build_platform_solver 包装——
                        # get_challenge 补全详情 + 下载附件 + 注入靶机地址，crypto/misc
                        # 附件题可被确定性预扫秒解（原 _to_question attachments=[] 附件题无法秒解）。
                        solver = build_platform_solver(platform, use_mock=False, core_solver=_race)
                    for ch in ranked[:solve_top]:
                        if sp.is_solved(str(ch.id)):
                            continue
                        print(f"--- 抢: {ch.id} {ch.title[:30]} ---")
                        out = await solver(ch)
                        flag = out.get("flag")
                        if flag:
                            result = await platform.submit_flag(str(ch.id), flag)
                            print(f"  提交 {ch.id}: accepted={result.accepted} "
                                  f"detail={result.detail[:50]}")
                            if result.accepted:
                                sp.mark_solved(str(ch.id), flag=flag, note="firstblood-watch")
                                print(f"  🎯 抢下一血: {flag}")
                        else:
                            print(f"  未解出（{ch.id} 换下一题）")
            else:
                # 已见题中是否有刚被他人解出的（排名变化监控）
                pass
        except KeyboardInterrupt:
            print("\n监控停止")
            return
        except Exception as exc:
            print(f"轮询异常（{exc}），继续监控")
        await asyncio.sleep(interval)


async def main() -> None:
    parser = argparse.ArgumentParser(description="抢一血快速扫描器")
    parser.add_argument("--probe", action="store_true", help="仅全遍历排序报告")
    parser.add_argument("--solve", action="store_true", help="全遍历 + 对最简单题走模板兜底")
    parser.add_argument("--watch", action="store_true",
                        help="公告轮询模式：新题开放瞬间自动触发抢一血")
    parser.add_argument("--interval", type=float, default=15.0, help="轮询间隔秒数（watch 模式）")
    parser.add_argument("--top", type=int, default=3, help="尝试前 N 道最简单题")
    args = parser.parse_args()

    from ctfplatform.dasctf import DasCTFPlatform

    platform = DasCTFPlatform()
    if not platform.base_url:
        print("FAIL: 未配置平台地址")
        return

    if args.watch:
        await watch(platform, interval=args.interval, solve_top=args.top)
        return

    print("=== 抢一血全遍历扫描 ===")
    try:
        ranked = await scan(platform)
    except Exception as exc:
        print(f"扫描失败: {exc}")
        return

    if not ranked:
        print("当前无可抢题目（全部已解出或未开放）")
        return

    print(f"未解且开放的题目 {len(ranked)} 道，按难度+分数排序（越靠前越先抢）:")
    for i, ch in enumerate(ranked, 1):
        extra = ch.extra or {}
        print(f"  #{i} {ch.id} [{extra.get('difficulty')}] {ch.title[:30]} "
              f"(score={extra.get('score')})")

    if args.solve:
        from run import build_race_solver
        from _race_start import _race_profile

        from run import build_platform_solver, build_race_solver
        _race = build_race_solver(use_mock=False, **_race_profile())
        # B-23 修复：复用 build_platform_solver（详情补全+附件下载+靶机注入）
        solver = build_platform_solver(platform, use_mock=False, core_solver=_race)
        print(f"\n=== 对前 {args.top} 道最简单题走模板兜底抢一血 ===")
        for ch in ranked[: args.top]:
            print(f"--- 抢: {ch.id} {ch.title[:30]} ---")
            out = await solver(ch)
            flag = out.get("flag")
            if flag:
                result = await platform.submit_flag(str(ch.id), flag)
                print(f"  提交 {ch.id}: accepted={result.accepted} "
                      f"detail={result.detail[:50]}")
                if result.accepted:
                    print(f"  🎯 抢下一血: {flag}")
            else:
                print(f"  未解出（{ch.id} 换下一题）")


def _extract_targets(extra: dict) -> list[str]:
    """从题目 extra 提取靶机地址（endpoints/portMappings/exposeIps/proxyIps）。

    正式赛实测结构（get_challenge 详情）：
        endpoints: [{proxyIps:["1.14.76.59"], ports:["http/80"],
                     portMappings:[{type:"http", port:"80", proxy:"15445"}],
                     exposeIps:["1.14.76.59:15445"], isProxy:True, ...}]
    拼装规则：http://<proxyIp>:<proxyPort>（isProxy 时用 proxy 端口），
    否则 http://<exposeIp> 直连。
    """
    targets: list[str] = []
    eps = extra.get("endpoints") or []
    if isinstance(eps, dict):
        eps = [eps]
    for ep in eps if isinstance(eps, list) else []:
        if not isinstance(ep, dict):
            continue
        proxy_ips = ep.get("proxyIps") or []
        expose_ips = ep.get("exposeIps") or []
        mappings = ep.get("portMappings") or []
        is_proxy = bool(ep.get("isProxy") or ep.get("is_proxy"))
        # 端口映射：http/80 → proxy 15445
        for pm in mappings if isinstance(mappings, list) else []:
            if not isinstance(pm, dict):
                continue
            _proto = str(pm.get("type") or "http").lower()
            _host = (proxy_ips[0] if is_proxy and proxy_ips
                     else expose_ips[0] if expose_ips else "")
            _port = pm.get("proxy" if is_proxy else "port") or pm.get("port")
            if _host:
                _scheme = "https" if _proto in ("https", "wss") else "http"
                targets.append(f"{_scheme}://{_host}:{_port}" if _port
                               else f"{_scheme}://{_host}")
        if not targets:
            for _ip in expose_ips:
                _s = str(_ip)
                if "://" in _s:
                    targets.append(_s)
                elif ":" in _s:  # host:port
                    targets.append(f"http://{_s}")
                else:
                    targets.append(f"http://{_s}")
        for _ip in proxy_ips:
            if _ip and _ip not in "".join(targets):
                targets.append(f"http://{_ip}")
    # 去重保序
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _to_question(ch):
    """平台题目 → solver Question 对象（含附件/靶机信息）"""
    extra = ch.extra or {}
    class _Q:
        pass
    q = _Q()
    q.id = str(ch.id)
    q.title = ch.title
    q.category = ch.category
    q.description = ch.description or ""
    q.flag_pattern = r"flag\{[^}]+\}"
    q.attachments = []
    q.extra = {"platform_challenge": True, "platform_meta": extra}
    # O1 联动修复（2026-08-21）：平台 difficulty 提升到 extra 顶层——
    # main_agent 读 question.extra.difficulty 做分级墙钟（EASY 120s 抢一血 /
    # HARD 600s 深推）与高难题首步重型升级，只放 platform_meta 子键里取不到。
    if extra.get("difficulty"):
        q.extra["difficulty"] = extra["difficulty"]
    # ── P0 修复（2026-08-21 正式赛）：靶机地址注入——列表接口无 endpoints，
    #    get_challenge 详情才有；把靶机 URL 拼进 description（web 题 has_target
    #    判定 + LLM 提示词可见），并挂 q.extra["targets"] 供工具层直接使用。──
    _targets = _extract_targets(extra)
    if _targets:
        q.extra["targets"] = _targets
        if "靶机" not in q.description:
            q.description = (q.description + "\n" if q.description else "") + \
                "靶机地址: " + " ".join(_targets)
    return q


if __name__ == "__main__":
    asyncio.run(main())
