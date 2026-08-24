"""测试赛做题启动器：平台轮询拉题 → 解题 → 提交 flag。

安全设计：
- access key 从环境变量读取（不经 shell 参数/命令行，避免凭据泄漏）
- 用法（先设置环境变量，再运行本脚本）：
    setx CTF_AGENT_PLATFORM_TOKEN "你的accesskey"
    python scripts/_race_start.py --probe    # 仅探测平台连通性+拉题数（不解题）
    python scripts/_race_start.py --once     # 跑一轮（拉题→解题→提交）
    python scripts/_race_start.py --forever  # 定时轮询（测试赛主循环，默认30s）
"""

import argparse
import asyncio
import os
import subprocess  # 模块级：_e2e_preflight 门禁 + _kill_stale_races 共用（可被测试 monkeypatch）
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 环境变量：DASCTF_TOKEN 优先（注册表已固化正确 accesskey），
# CTF_AGENT_PLATFORM_TOKEN 次之（env 里残留的是测试赛错误 token 40403 无权）。
# ⚠️ 顺序不可颠倒：DASCTF_TOKEN 是正式赛正确 accesskey，必须先取。
TOKEN_ENV_NAMES = ("DASCTF_TOKEN", "CTF_AGENT_PLATFORM_TOKEN")
BASE_URL_ENV_NAMES = ("DASCTF_BASE_URL", "CTF_AGENT_PLATFORM_BASE_URL")


def _env_or_registry(name: str) -> str:
    """读环境变量；当前进程读不到时回退注册表（setx 后新进程才生效的坑）。"""
    val = os.getenv(name, "").strip()
    if val:
        return val
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            value, _ = winreg.QueryValueEx(k, name)
            return str(value).strip()
    except OSError:
        return ""


def _get_token() -> str:
    for name in TOKEN_ENV_NAMES:
        val = _env_or_registry(name)
        if val:
            return val
    return ""


def _get_base_url() -> str:
    for name in BASE_URL_ENV_NAMES:
        val = _env_or_registry(name)
        if val:
            return val
    return ""


def _kill_stale_races() -> None:
    """启动前自动杀掉残留的 _race_start 进程（P0 互斥，初赛 5 进程并发互踩教训）。

    原理：Windows 下用 WMI 查所有 python.exe 且命令行含 _race_start 的进程，
    排除自身（当前 PID），其余全部 Stop-Process。
    """
    import subprocess
    try:
        script = (
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -eq 'python.exe' -and "
            "$_.CommandLine -like '*_race_start*' -and "
            f"$_.ProcessId -ne {os.getpid()} }} | "
            "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; "
            "Write-Output ('killed ' + $_.ProcessId) }"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip()
        killed = [l for l in out.splitlines() if l.startswith("killed ")]
        if killed:
            print(f"🧹 已清理 {len(killed)} 个残留 _race_start 进程（进程互斥保护）: {', '.join(killed)}")
        else:
            print("🧹 无残留 _race_start 进程（干净）")
    except Exception as exc:  # noqa: BLE001 - 清理失败不阻塞启动
        print(f"[~] 残留进程清理跳过（{str(exc)[:50]}）")


# ── 多模型矩阵竞速档位（限流备案，env 控制，不改核心循环）────────
# CTF_AGENT_RACE_PROFILE = full(6路) | medium(4路) | minimal(2路)
# full: qwen3.7-plus + qwen3.8-max(百炼免费) + deepseek(充值兜底) +
#       tokenhub deepseek-v4-pro(腾讯免费重型) + xfyun lite(永久免费) + glm-4.7(智谱免费)
# medium: 去掉 tokenhub + glm（4 路，qwen 主源 + deepseek + xfyun）
# minimal: 仅 qwen3.7-plus + deepseek（2 路，限流保底）
RACE_PROFILES = {
    "full": dict(
        models=("qwen3.7-plus", "qwen3.8-max"),
        providers=("deepseek",),
        tokenhub_models=("deepseek-v4-pro",),
        extra_models=(("xfyun", "lite"), ("glm", "glm-4.7")),
    ),
    "medium": dict(
        # P0 修复（2026-08-21 赛后）：deepseek 402 余额耗尽、qwen 403 额度耗尽，
        # medium 档改用实测存活源（千帆主 + moonshot + ark 均 200 OK）。
        models=(),
        providers=("baidu", "moonshot", "ark"),
        tokenhub_models=(),
        extra_models=(("glm", "glm-4.7"),),
    ),
    "minimal": dict(
        models=(),
        providers=("baidu", "moonshot"),   # 实测存活源（保底 2 路，千帆主）
        tokenhub_models=(),
        extra_models=(),
    ),
    # P0 修复（2026-08-21 17:15 赛后）：默认档位 = 千帆主源 + moonshot/ark 备选。
    # 千帆 ernie-3.5 为全系统最强单源（测试赛 72.4% 跑分，超 DeepSeek 基线），
    # 当前实测 200 OK；moonshot/ark 为正式赛末段实测存活源。熔断器会在
    # 任一源 401/402/403 连续失败时自动剔除，剩余存活源自动接管。
    "live": dict(
        models=(),
        providers=("baidu", "moonshot", "ark"),
        tokenhub_models=(),
        extra_models=(),
    ),
    # ultra（2026-08-21 用户要求"超多模型矩阵"）：覆盖所有白名单内且已配 key 的 provider。
    # 百炼 qwen×2（主攻）+ DeepSeek(充值兜底,attempt≥2升reasoner) + 千帆(ernie免费)
    # + 智谱(glm-4.7 + glm-5.3/5.2 狠狠榨干23号到期额度) + 讯飞(lite无限)
    # + TokenHub 4 主力(deepseek-v4-pro/kimi-k3/hy3/deepseek-v4-flash)
    # + 豆包(doubao 200万/日) + Kimi(moonshot) + 硅基 + 商汤。
    # 共 16 路竞速；任一先得有效 flag 即胜。429 限流由 client 熔断器自动剔除坏源。
    # 注意：TokenHub 4 路 + 智谱 3 路会并发打同一端点，免费额度下可能 429（不致命，
    # 其它源兜底）；若限流严重，赛中改 CTF_AGENT_RACE_PROFILE=full(6路)/live(3路) 即降级。
    "ultra": dict(
        # 实测存活源（2026-08-21 18:30 全量探测，HTTP200 通过）
        models=("qwen-plus",),                        # 百炼：qwen3.7/3.8 免费额度耗尽403，qwen-plus 实测200
        providers=("baidu", "glm", "xfyun"),         # 千帆ernie(最强单源)+智谱优先级key+讯飞lite无限；deepseek官方402已剔除
        tokenhub_models=("hy3", "deepseek-v4-flash"),  # 腾讯免费包：深V4-Pro额度耗尽402、kimi-k3持续超时已剔除
        extra_models=(("ark", "doubao-seed-2-1-pro-260628"),  # 豆包200万/日
                      ("moonshot", "kimi-k2.6"),                # Kimi
                      ("glm", "glm-5.3"),                        # 智谱优先级key(23号到期狠榨)
                      ("glm", "glm-5.2"),                        # 智谱优先级key
                      ("mimo", "mimo-v2.5-pro")),                # 小米MiMo
        # 待修/耗尽（不进默认 ultra，避免 402/403 空转；修复或充值后启用）：
        #   SiliconFlow 402 余额0 | SenseNova 403 账号待控制台确认 | DeepSeek官方 402 余额不足
        #   TokenHub deepseek-v4-pro 402 | TokenHub kimi-k3 持续超时 | Qwen qwen3.7/3.8 403
    ),
}


def _race_profile() -> dict:
    """按 CTF_AGENT_RACE_PROFILE 返回竞速矩阵配置。

    P0 修复（2026-08-21 赛后）：默认档位从 medium 改为 live——
    medium 的唯一 provider deepseek 正式赛 402 余额耗尽，裸用会 0 解出空转；
    live（moonshot+ark）为实测 HTTP 200 存活源，且 llm.client 熔断器会在
    运行中自动剔除 401/402/403 失效源，剩余存活源自动接管。
    """
    profile = os.getenv("CTF_AGENT_RACE_PROFILE", "live").strip().lower()
    return RACE_PROFILES.get(profile, RACE_PROFILES["live"])


def _race_profile_label() -> str:
    """当前档位人类可读标签。"""
    profile = os.getenv("CTF_AGENT_RACE_PROFILE", "live").strip().lower()
    if profile == "minimal":
        return "minimal(2路: deepseek)"
    if profile == "medium":
        return "medium(1路: deepseek——已失效勿用!)"
    if profile == "live":
        return "live(3路: 千帆主+moonshot+ark——实测存活)"
    if profile == "ultra":
        return "ultra(11路实测存活: 百炼qwen-plus+千帆+智谱×3+讯飞+TokenHub×2+豆包+Kimi+MiMo)"
    return "full(6路: qwen×2+deepseek+tokenhub+xfyun+glm)"


async def build_poller(solver_enabled: bool):
    """构建 PlatformPoller（solver_enabled=False 时只拉题不解题）。"""
    from ctfplatform.dasctf import DasCTFPlatform
    from ctfplatform.poller import PlatformPoller

    platform = DasCTFPlatform(base_url=_get_base_url(), token=_get_token())
    if not platform.base_url:
        print("FAIL: 未配置平台地址（DASCTF_BASE_URL）")
        return None
    token = _get_token()
    if not token:
        print("FAIL: 未配置平台 access key（设置 CTF_AGENT_PLATFORM_TOKEN 环境变量）")
        return None
    # token 已通过环境变量注入平台客户端（不在命令行出现）

    solver = None
    if solver_enabled:
        from run import build_race_solver, build_platform_solver

        # 多模型矩阵 v2（2026-08-21 08:50，实测数据支撑）：qwen 主源 6 路。
        # 同 8 道真真题实测：qwen3.7-plus 8/8=100% vs deepseek-chat 4/8=50%。
        # 矩阵 = 百炼 qwen 2 路主攻（免费）+ deepseek 兜底（attempt≥2 升 reasoner）
        #        + tokenhub 免费重型 + xfyun/glm 免费保底。
        # 数学引擎（确定性攻击链）优先级最高，命中即秒解。
        # 限流备案：CTF_AGENT_RACE_PROFILE=full(6路)|medium(4路)|minimal(2路)
        cfg = _race_profile()
        race = build_race_solver(use_mock=False, **cfg)
        # 用 build_platform_solver 包装：ChallengeInfo→Question（下载附件+注入靶机）
        # poller 期望 callable(challenge_info)->dict，build_race_solver 签名不匹配且不下载附件
        solver = build_platform_solver(platform, use_mock=False, core_solver=race)
        n = len(cfg["models"]) + len(cfg["providers"]) + len(cfg["tokenhub_models"]) + len(cfg["extra_models"])
        print(f"多模型矩阵已构建（{n} 路竞速：{_race_profile_label()} + 数学引擎优先 + 附件下载）")

    poller = PlatformPoller(platform=platform, solver=solver)
    return poller


async def _e2e_preflight(timeout: float = 180.0) -> bool:
    """--compete 强制 e2e 数据链路预检（锐评 A3：e2e 从"口头铁律"变代码门禁）。

    初赛教训（2026-08-21）：赛前从未用真实平台端到端跑通一道题，API 字段错配
    导致 62 题空数据空转 3 小时 0 分。开赛前强制抽样验证"平台能给出题面/
    附件/靶机"，失败即拒绝开战（fail-closed）。

    返回 True=允许开赛；False=拒绝。
    - exit 0: 链路通过（含"平台已开放但暂 0 题"——开赛前正常）
    - exit 1: 数据链路失败 / exit 2: 平台未配置或不可达 → 都拒绝
    - 超时 → 拒绝
    """
    cmd = [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                        "scripts", "_e2e_verify.py")]
    print("=== 🛡 e2e 数据链路预检（锐评 A3 门禁：不过不开战）===")
    try:
        proc = await asyncio.to_thread(subprocess.run, cmd,
                                       capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        print(f"❌ e2e 预检无法执行（{exc}）——拒绝开赛。修复后重跑，或刚跑过全绿可 --skip-e2e。")
        return False
    out = (proc.stdout or "") + (proc.stderr or "")
    tail = out.strip().splitlines()[-20:]
    print("\n".join(tail))
    if proc.returncode == 0:
        print("✅ e2e 预检通过——允许开赛")
        return True
    print(f"❌ e2e 预检未通过（exit={proc.returncode}）——拒绝开战（fail-closed）。")
    print("   修复数据链路后重跑；或刚跑过 `bash setup.sh --e2e` 全绿时用 --skip-e2e 豁免。")
    return False


async def main() -> None:
    parser = argparse.ArgumentParser(description="西湖论剑测试赛做题启动器")
    parser.add_argument("--probe", action="store_true", help="仅探测平台连通性与题目数")
    parser.add_argument("--once", action="store_true", help="跑一轮（拉题→解题→提交）")
    parser.add_argument("--forever", action="store_true", help="定时轮询（默认30s，测试赛主循环）")
    parser.add_argument("--firstblood", action="store_true",
                        help="抢一血模式：进场全遍历→难度排序→模板直出（最快路径）→立即提交")
    parser.add_argument("--compete", action="store_true",
                        help="正式赛一键作战：抢一血 → 稳定轮询解题 → 收尾生成解题报告（全流程）")
    parser.add_argument("--interval", type=float, default=30.0, help="轮询间隔秒数")
    parser.add_argument("--burst", type=float, default=5.0,
                        help="放题高频窗口轮询间隔秒数（默认 5s，P0 修复：原 3s 触发 429 风暴；poller 层钳制下限 5s）")
    parser.add_argument("--burst-duration", type=float, default=60.0,
                        help="放题高频窗口持续时间秒（默认 60s，P0 修复：原 180s 高频窗口过长）")
    parser.add_argument("--skip-e2e", action="store_true",
                        help="跳过 --compete 的强制 e2e 数据链路预检（仅在刚跑过 bash setup.sh --e2e 全绿时使用）")
    args = parser.parse_args()

    # P0 进程互斥（初赛 5 进程并发互踩教训）：启动前自动清理残留 _race_start
    # 仅作战模式清理（--probe 只读探测不需要杀进程）
    if not args.probe:
        _kill_stale_races()

    # 生效配置快照（2026-08-22 锐评第五节整改）：开赛前 5 秒人工核对
    # provider/端点/模型/key 状态/白名单/残留变量——防 BASE_URL 残留全瘫重演。
    try:
        from config import print_effective_config_snapshot

        print_effective_config_snapshot()
    except Exception as _snap_exc:  # noqa: BLE001 - 快照失败不阻塞启动
        print(f"⚠️ 配置快照打印失败（不影响启动）: {_snap_exc}")

    token = _get_token()
    if not token:
        print("提示: 请先设置 access key 环境变量后再运行")
        print("  setx CTF_AGENT_PLATFORM_TOKEN \"你的accesskey\"")
        print("  （重新打开终端生效，或本会话内用 set CTF_AGENT_PLATFORM_TOKEN=...）")
        # 仍尝试探测连通性（平台地址可达性）
        from ctfplatform.dasctf import DasCTFPlatform

        p = DasCTFPlatform(base_url=_get_base_url(), token=token)
        print(f"平台地址: {p.base_url or '(未配置)'}")
        if p.base_url:
            ok = await p.discover_openapi()
            print(f"openapi 探测: {'成功' if ok else '失败/跳过（可能无需）'}")
        return

    if args.compete:
        # 正式赛一键作战：① 抢一血（模板直出最快路径）② 稳定轮询解题 ③ 收尾生成报告
        print("=== 🏁 正式赛一键作战模式 ===")
        # 阶段⓪：强制 e2e 数据链路预检（锐评 A3）——开赛前验证"平台能给解题数据"，
        # 不过不开战。2026-08-21 初赛：无此门禁 → 62 题空数据空转 3 小时 0 分。
        if not args.skip_e2e:
            if not await _e2e_preflight():
                print(f"手动复检：{sys.executable} scripts/_e2e_verify.py")
                return
        # 阶段①：抢一血——进场全遍历 → 难度排序 → 模板直出 → 立即提交
        try:
            from scripts._scan_firstblood import scan, _to_question
        except ImportError:
            from _scan_firstblood import scan, _to_question
        from run import build_race_solver
        from core.solve_progress import get_progress

        sp = get_progress()
        poller = await build_poller(solver_enabled=True)
        if poller is None:
            return
        platform = poller.platform
        # 同步平台 hasSolved 到状态锁（防绕远路）
        try:
            synced = await platform.list_challenges()
            for ch in synced:
                if (ch.extra or {}).get("hasSolved"):
                    sp.mark_solved(str(ch.id), note="platform hasSolved")
            print(f"[进度中心] 已同步，未解 {len(sp.filter_unsolved(synced))} 道")
        except Exception as exc:
            print(f"[进度中心] 同步跳过（{exc}）")

        ranked = await scan(platform)
        if ranked:
            print(f"🎯 抢一血扫描：{len(ranked)} 道未解，按难度排序")
            for ch in ranked[:6]:  # 抢最容易的 6 题（crypto/web 优先，确定性工具秒解）
                if sp.is_solved(str(ch.id)):
                    continue
                print(f"--- 抢: {ch.id} {ch.title[:30]} ---")
                # 先拉详情（含附件/靶机）——列表摘要无 attachment 字段，crypto 题拿不到附件无法解
                try:
                    detail = await platform.get_challenge(str(ch.id))
                    if detail and (detail.extra or {}):
                        ch = detail
                except Exception as _e:  # noqa: BLE001 - 详情拉取失败仍用摘要尝试
                    pass
                # 用 poller.solver（build_platform_solver 包装，会下载附件 + 注入靶机）
                out = await poller.solver(ch)
                flag = out.get("flag")
                if flag:
                    # submit_serialized 返回 tuple(submitted, accepted, detail)
                    _sub, accepted, detail = await poller.submit_serialized(str(ch.id), flag)
                    print(f"  提交 {ch.id}: accepted={accepted} detail={detail[:50]}")
                    if accepted:
                        sp.mark_solved(str(ch.id), flag=flag, note="compete-firstblood")
                        print(f"  🎯 抢下一血: {flag}")
                else:
                    print(f"  未解出（{ch.id} 进入轮询阶段）")
        else:
            print("当前无可抢题目，直接进入稳定轮询")

        # 阶段②：稳定轮询解题（forever）
        print(f"\n=== 稳定轮询解题（间隔 {args.interval}s，Ctrl+C 结束并生成报告）===")
        try:
            await poller.run_forever(interval=args.interval,
                                     fast_interval=args.burst, fast_duration=args.burst_duration)
        except KeyboardInterrupt:
            print("\n作战结束，生成解题报告...")

        # 阶段③：收尾生成解题报告（手册第 8 条硬性要求）
        try:
            from report.generator import generate_report, save_report
            from run import _solve_logs

            md = generate_report(poller_records=poller.records(), solve_logs=_solve_logs)
            path = save_report(md)
            print(f"\n📋 解题报告已生成: {path}")
        except Exception as exc:
            print(f"解题报告生成跳过（{exc}）")
        print(poller.summary())
        return

    if args.firstblood:
        # 抢一血模式：进场全遍历 → 难度/分数排序 → 模板直出最快路径 → 立即提交
        try:
            import sys as _sys
            from scripts._scan_firstblood import scan
        except ImportError:
            # 直接以脚本方式导入（模块路径兜底）
            from _scan_firstblood import scan
        from run import build_platform_solver, build_race_solver
        from core.solve_progress import get_progress

        sp = get_progress()
        poller = await build_poller(solver_enabled=False)
        if poller is None:
            return
        platform = poller.platform
        print("=== 🎯 抢一血模式：进场全遍历 ===")
        ranked = await scan(platform)
        if not ranked:
            print("当前无可抢题目（全部已解出或未开放）")
            return
        for i, ch in enumerate(ranked, 1):
            extra = ch.extra or {}
            print(f"  #{i} {ch.id} [{extra.get('difficulty')}] {ch.title[:30]} "
                  f"(score={extra.get('score')})")
        # 多模型矩阵 v2：与 compete/轮询阶段同一竞速档位（qwen 主源，限流可降级）
        # P1-5 修复（2026-08-21 赛后）：--firstblood 复用 build_platform_solver——
        # 原 _to_question 设 attachments=[] 不下载附件，crypto/misc 附件题完全无法秒解。
        # build_platform_solver 会 get_challenge 补全详情 + 下载附件 + 注入靶机地址，
        # 与 --compete 路径一致，让 crypto/misc 附件题可被确定性预扫秒解。
        race = build_race_solver(use_mock=False, **_race_profile())
        platform_solver = build_platform_solver(platform, use_mock=False, core_solver=race)
        for ch in ranked[:4]:
            if sp.is_solved(str(ch.id)):
                print(f"跳过 {ch.id}（已被其他会话解出）")
                continue
            print(f"--- 抢: {ch.id} {ch.title[:30]} ---")
            out = await platform_solver(ch)
            flag = out.get("flag")
            if flag:
                # submit_serialized 返回 tuple(submitted, accepted, detail)
                _sub, accepted, detail = await poller.submit_serialized(str(ch.id), flag)
                print(f"  提交 {ch.id}: accepted={accepted} "
                      f"detail={detail[:50]}")
                if accepted:
                    sp.mark_solved(str(ch.id), flag=flag, note="firstblood")
                    print(f"  🎯 抢下一血: {flag}")
            else:
                print(f"  未解出（{ch.id} 换下一题）")
        return

    if args.probe or not (args.once or args.forever):
        poller = await build_poller(solver_enabled=False)
        if poller is None:
            return
        platform = poller.platform
        # ① 先打原始请求校验业务码：HTTP 200 但业务码非 00000 仍属失败
        #    （如 40403 无权操作 = token 无权限/赛事未开放）。旧版硬编码
        #    "平台连通 OK" 会把鉴权失败误报成连通正常（初赛空转 3h 0 分根因之一）。
        raw = await platform._request("GET", "challenges")
        if not raw:
            print("❌ 平台请求失败（HTTP 层错误/429/5xx/网络不可达）——未连通")
            return
        biz_code = str(raw.get("code", ""))
        biz_msg = str(raw.get("message", ""))
        if biz_code not in ("00000", "") or "无权" in biz_msg or "无效" in biz_msg:
            print(f"❌ 平台鉴权/权限异常：业务码 {biz_code}（{biz_msg}）")
            print("   → token 无权限或赛事未开放，无法拉题（利用终止）。")
            print("   处置：确认当前是否有开放赛事；如有，更新 DASCTF_TOKEN 为正确 access key 后重跑。")
            return
        challenges = await platform.list_challenges()
        print(f"平台连通 OK（业务码 {biz_code}），拉取到 {len(challenges)} 道题")
        for ch in challenges[:10]:
            print(f"  - {ch.id} [{ch.category}] {ch.title[:40]}")
        # 同步平台 hasSolved → 本地状态锁（供跨会话查询）
        try:
            from core.solve_progress import get_progress

            sp = get_progress()
            for ch in challenges:
                if (ch.extra or {}).get("hasSolved"):
                    sp.mark_solved(str(ch.id), note="platform hasSolved")
            unsolved = sp.filter_unsolved(challenges)
            print(f"已解出 {len(challenges) - len(unsolved)}/{len(challenges)}，"
                  f"未解 {len(unsolved)} 道（跨会话状态锁已同步）")
        except Exception as exc:  # 状态锁失败不阻塞探测
            print(f"状态锁同步跳过（{exc}）")
        return

    poller = await build_poller(solver_enabled=True)
    if poller is None:
        return
    # 进题前：同步平台 hasSolved 到状态锁，跳过已被其他会话解出的题
    try:
        from core.solve_progress import get_progress

        sp = get_progress()
        synced = await poller.platform.list_challenges()
        for ch in synced:
            if (ch.extra or {}).get("hasSolved"):
                sp.mark_solved(str(ch.id), note="platform hasSolved")
        unsynced = sp.filter_unsolved(synced)
        if len(unsynced) < len(synced):
            print(f"[进度中心] 已有 {len(synced) - len(unsynced)} 道被解出，"
                  f"剩余 {len(unsynced)} 道待攻（避免重复攻坚）")
    except Exception as exc:
        print(f"[进度中心] 同步跳过（{exc}）")
    if args.once:
        records = await poller.run_once()
        _print_records(records)
    else:
        print(f"开始定时轮询（间隔 {args.interval}s，Ctrl+C 停止）")
        try:
            await poller.run_forever(interval=args.interval,
                                     fast_interval=args.burst, fast_duration=args.burst_duration)
        except KeyboardInterrupt:
            print("\n轮询停止，汇总:")
            print(poller.summary())


def _print_records(records) -> None:
    if not records:
        print("本轮无新题")
        return
    for r in records:
        print(f"[{r.challenge_id}] {r.title[:30]} flag={'有' if r.flag else '无'} "
              f"提交={'是' if r.submitted else '否'} accepted={r.accepted} "
              f"detail={r.detail[:40]}")


if __name__ == "__main__":
    asyncio.run(main())
