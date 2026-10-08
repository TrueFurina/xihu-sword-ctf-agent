"""赛前环境验证脚本（锐评「环境不可用=出局」修复——2026-08-22）。

正式赛 0 解出锐评：比赛环境 python 输出无响应/链路 40403/大文件超时——
「比赛中系统不可用 = 直接出局」。本脚本赛前验证环境 100% 可用：
1. python 输出可用性（跑简单脚本确认输出正常——0 解出期间输出无响应的预防）
2. 链路验证（拉题 exercise-list 非 40403——AccessKey 有效）
3. 大文件处理（mmap 快速扫——16MB 级不超时）
4. 网关/配置确认（LLM_BASE_URL/HEAVY_MODEL/ENFORCE）
5. LLM 主链可达性（2026-10-08 补齐——**对当前生效 provider 真发一次最小请求**）

用法：
    python scripts/_preflight_env.py                 # ①②③④ + ⑤ 提示（不联网）
    python scripts/_preflight_env.py --probe-llm     # 连 ⑤ 一起真验；全部 PASS 才可开赛

⚠️ 第 ⑤ 项为什么不默认跑：provider 可用性随余额/欠费/平台策略变化，门禁不应因为
   欠费而永久变红；但同样不能悄悄跳过让人误以为验过了。所以默认输出明确标记
   「未探测」，且**不计入 PASS** —— 没验过 LLM 就不输出「可开赛」（fail-closed）。

历史缺口（2026-10-08 修复）：本脚本曾自我宣称「验证环境 100% 可用、全部 PASS
才可开赛」，但 ①②③④ 四项**没有一项验证 LLM 提供真能发通请求**；而 provider 恰
是全链路最常失效的一环。结果是「门禁全绿 → 判定可开赛 → 一开赛 LLM 全瘫」。
红是提示，绿是承诺 —— 漏验最会失效的那一环，等于把承诺给错了对象。
"""

import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def check_python_output() -> bool:
    """① python 输出可用性——跑简单脚本确认输出正常（0 解出期间无响应预防）。"""
    code = "import sys; print('PY_OUT_OK', flush=True)"
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, timeout=30)
        ok = r.returncode == 0 and "PY_OUT_OK" in (r.stdout or "")
        print(f"① python 输出: {'✅ 正常' if ok else '❌ 无响应（' + str(r.stderr)[:60] + '）'}")
        return ok
    except Exception as e:  # noqa: BLE001
        print(f"① python 输出: ❌ 异常 {type(e).__name__}")
        return False


def check_link(access_key: str = "", base_url: str = "https://pro.dasctf.com") -> bool:
    """② 链路验证——拉题 exercise-list 非 40403（AccessKey 有效）。"""
    import httpx

    ak = access_key or os.getenv("DASCTF_TOKEN", "")
    if not ak:
        print("② 链路: ❌ DASCTF_TOKEN 未配置")
        return False
    try:
        r = httpx.get(f"{base_url}/slab-match/api/v1/agent/ctf/exercise-list",
                      headers={"X-Agent-AccessKey": ak},
                      timeout=20, trust_env=False)
        code = r.json().get("code", "")
        ok = code == "00000"
        print(f"② 拉题链路: {'✅ 通（code=00000）' if ok else f'❌ {code}（' + r.text[:80] + '）'}")
        return ok
    except Exception as e:  # noqa: BLE001
        print(f"② 拉题链路: ❌ 异常 {type(e).__name__} {str(e)[:60]}")
        return False


def check_bigfile(path: str = "") -> bool:
    """③ 大文件处理——mmap 快速扫（16MB 级不超时）。"""
    if not path or not os.path.exists(path):
        print("③ 大文件: ⚠️ 未指定测试文件（跳过——可用 misc_bigfile_traffic skill 测）")
        return True
    try:
        from skills.misc_bigfile_traffic import _mmap_scan

        t0 = __import__("time").time()
        flags = _mmap_scan(path)
        dt = __import__("time").time() - t0
        print(f"③ 大文件: ✅ mmap 扫 {os.path.getsize(path)//1024//1024}MB 耗时 {dt:.1f}s（flag: {len(flags)}）")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"③ 大文件: ❌ {type(e).__name__} {str(e)[:60]}")
        return False


def check_config() -> bool:
    """④ 配置确认——网关/重型/白名单。

    2026-10-08：原实现还要求 `heavy == "deepseek-reasoner"`。那一行把某场比赛的
    具体选型钉进了通用门禁，而该源后来因余额状态变化再也发不通——照它判定，等于
    逼人配上一个当下打不通的模型才算「可开赛」。门禁只该验**结构性**要求：网关配了、
    重型模型非空、比赛模式开了强制白名单。「配的这个源此刻通不通」是第 ⑤ 项的事。
    """
    gw = os.getenv("CTF_AGENT_LLM_BASE_URL", "")
    heavy = os.getenv("CTF_AGENT_HEAVY_MODEL", "")
    enf = os.getenv("CTF_AGENT_ENFORCE_WHITELIST", "")
    ok = bool(gw) and "llm-gateway" in gw and bool(heavy.strip()) and enf == "1"
    print(f"④ 配置: {'✅' if ok else '❌'} 网关={'有' if gw else '无'} "
          f"重型={'已配' if heavy.strip() else '未配'} ENFORCE={enf}")
    return ok


def resolve_effective_provider() -> str:
    """当前实际会生效的 provider 裸值。

    刻意复用 `scripts/_facts.py::effective_provider_value()`（唯一的 provider 解析
    真相源），不在本文件再写一遍解析——否则两处各自漂移，正是本仓反复出现的故障模式。
    """
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    try:
        import _facts  # noqa: PLC0415 - 快照/检查内局部导入，避免顶层依赖

        return _facts.effective_provider_value()
    except Exception:  # noqa: BLE001 - 解析失败时降级为空串，由检查项自行报告
        return ""


def default_llm_probe(provider: str) -> tuple:
    """默认探测器：对 provider 发**一次最小** chat 请求，返回 (ok, detail)。

    只在显式 `--probe-llm` 时被调用——「可用」是随余额/欠费/平台策略变化的状态，
    不该让赛前门禁因欠费而永久变红；但同样不该悄悄跳过、让人误以为验过了。
    """
    try:
        if os.path.dirname(_HERE) not in sys.path:
            sys.path.insert(0, os.path.dirname(_HERE))
        from llm.client import ai_chat

        replies = ai_chat([{"role": "user", "content": "ping"}],
                          provider=provider or None, max_tokens=16)
    except Exception as e:  # noqa: BLE001 - 探针失败本身就是结论
        return False, f"{type(e).__name__} {str(e)[:80]}"
    if replies is None or replies == "":
        return False, "响应为空（Key 无效 / 端点不可达 / 模型不存在）"
    return True, f"响应正常（{str(replies)[:24]}…）"


def check_llm_reachability(probe=None) -> bool:
    """⑤ LLM 主链可达性——补齐赛前验证最大的缺口（2026-10-08）。

    本门禁自称「全部 PASS 才可开赛」，但原有 ①②③④ 四项**没有一项验证 LLM 真能
    发通请求**；而 provider 恰是全链路最常失效的一环（历史上一度 qwen 欠费、
    deepseek 402、baidu 403、moonshot 429 同时不可用）。结果是「门禁全绿、一开赛
    LLM 全瘫」——比某一项报红危险得多。

    Args:
        probe: 注入的探测回调 `probe(provider) -> (ok, detail)`。**默认 None = 不联网**，
            只报告当前生效 provider 并明确标记为「未探测」（返回 True，不阻断，
            与 ③ 大文件未指定文件时保持一致）。测试应始终注入 probe——见
            `tests/test_preflight_llm_reachability.py`：守卫失效时测试不得成为发射道。

    Returns:
        bool: 是否通过。未探测/通过均返回 True；显式探测失败返回 False。
    """
    provider = resolve_effective_provider()
    if not provider:
        print("⑤ LLM 主链: ❌ 解析不到生效 provider（env/config 均无）")
        return False
    if probe is None:
        print(f"⑤ LLM 主链: ⚠️ 未探测（当前生效 provider={provider}）"
              f"——加 --probe-llm 真发一次最小请求；本项不计入 PASS")
        return True
    try:
        ok, detail = probe(provider)
    except Exception as e:  # noqa: BLE001 - 探测器自身炸了也必须结论化为失败
        print(f"⑤ LLM 主链: ❌ provider={provider} 探针异常 {type(e).__name__} {str(e)[:60]}")
        return False
    print(f"⑤ LLM 主链: {'✅' if ok else '❌'} provider={provider} {detail}")
    return bool(ok)


def verdict(passed: int, total: int, probed: bool) -> str:
    """汇总结论文案。抽成纯函数，便于用合成数据自检（真实环境下「前四项全绿」

    这一分支在 CI 上几乎跑不到——不配合成自检的话，写坏它永远不会变红）。

    不变式：**没验过 LLM（probed=False）就绝不返回「可开赛」**，即使其余项全绿。
    """
    if passed >= total and probed:  # 还原 M3
        return "✅ 可开赛"
    if passed >= total - 1 and not probed:
        # 措辞刻意避开「可开赛」字面：一个「尚不可开赛」的结论里若出现该词，被摘抄
        # 后半句或被上层作包含匹配时就会误读成许可（「陈述离开关联上下文即失真」）。
        return "⚠️ 未验证 LLM 主链——加 --probe-llm 后方可判定（当前不得开赛）"
    return "❌ 修复后重跑"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="赛前环境验证")
    parser.add_argument("--probe-llm", action="store_true",
                        help="对当前生效 provider 真发一次最小 LLM 请求（极小成本），未指定则跳过 ⑤")
    args = parser.parse_args(argv)

    print("=" * 50)
    print("赛前环境验证（锐评「环境不可用=出局」修复）")
    print("=" * 50)
    # ⑤ 必须最后跑（它要在前四项之后打印，且不吃前四项的任何状态）
    results = [check_python_output(), check_link(), check_bigfile(), check_config()]
    if args.probe_llm:
        results.append(check_llm_reachability(default_llm_probe))
    else:
        # 只打印「未探测」提示，**不计入 PASS**：没验过 LLM 就不能宣称「可开赛」。
        check_llm_reachability(None)

    passed = sum(results)
    # 总数自动跟随检查项数（+ 未探测的 ⑤），避免每加一项都要回头改通过条件。
    # ⑤ 未探测时不进 passed，故恒 < total → 永不误报「可开赛」（fail-closed）。
    total = len(results) + (0 if args.probe_llm else 1)
    verdict_text = verdict(passed, total, bool(args.probe_llm))
    print(f"\n结果: {passed}/{total} PASS——{verdict_text}")
    return 0 if verdict_text.startswith("✅") else 1


if __name__ == "__main__":
    sys.exit(main())
