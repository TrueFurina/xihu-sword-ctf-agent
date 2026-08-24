# -*- coding: utf-8 -*-
"""赛前 10 分钟检查清单（锐评第六节落地）：
    python scripts/_preflight.py           # 全项检查（provider/平台/回归/报告）
    python scripts/_preflight.py --clean   # 清理测试数据后全项检查（赛前推荐）

检查项：
1. LLM provider 可用性（7 免费源 + deepseek/qwen 状态）
2. 平台连通性（DASCTF_BASE_URL + token）
3. 本地 3 题快速回归（主循环/工具/校验链路）
4. 解题报告生成路径
5. 合规环境变量（ENFORCE_WHITELIST / ALLOW_HUMAN 等）
"""
import argparse
import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 白名单免费 provider（探测顺序 = 优先级）
PROVIDERS = [
    ("baidu", "百度千帆", "QIANFAN_API_KEY"),
    ("tokenhub", "腾讯TokenHub", "TOKENHUB_API_KEY"),
    ("mimo", "小米 MiMo", "MIMO_API_KEY"),
    ("glm", "智谱 GLM", "ZHIPU_API_KEY"),
    ("deepseek", "DeepSeek 官方", "DEEPSEEK_API_KEY"),
    ("qwen", "阿里百炼", "DASHSCOPE_API_KEY"),
    ("tencent", "腾讯混元", "HUNYUAN_API_KEY"),
    ("xfyun", "讯飞星火", "XFYUN_API_KEY"),
    ("siliconflow", "硅基流动", "SILICONFLOW_API_KEY"),
    ("moonshot", "月之暗面", "MOONSHOT_API_KEY"),
    ("ark", "字节豆包", "ARK_API_KEY"),
]

def _has_key(name: str) -> bool:
    try:
        from config import _env_or_registry
        return bool(_env_or_registry(name))
    except Exception:
        return bool(os.getenv(name, "").strip())

def _probe_provider_http(pname: str) -> tuple[str, str]:
    """真实 HTTP 探测单 provider（非 ai_chat 全链路，避免内部逻辑干扰）。

    返回 (状态, 说明)。状态: OK / NOKEY / FAIL / NOLIVE。
    修复（2026-08-21 17:05 P0）：正式赛最后 10 分钟才手动发现 moonshot/ark 存活
    （deepseek 402/qwen 403/千帆 401 全挂）。preflight 必须真实 HTTP 探测，
    能区分 200/401/402/403/429，而不是 ai_chat 返回空就笼统报"不可用"。
    """
    from config import _env_or_registry, _resolve_provider_defaults

    keyenv = next((k for p, _, k in PROVIDERS if p == pname), "")
    if not keyenv:
        return "NOLIVE", "未知 provider"
    key = _env_or_registry(keyenv)
    if not key:
        return "NOKEY", f"无 {keyenv}"
    try:
        base_url, model = _resolve_provider_defaults(pname)
    except Exception:
        base_url, model = "", ""
    if not base_url:
        return "NOLIVE", "无默认端点"
    import httpx
    try:
        r = httpx.post(
            base_url,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json={"model": model,
                  "messages": [{"role": "user", "content": "hi"}],
                  "max_tokens": 5},
            timeout=12,
        )
        if r.status_code == 200:
            return "OK", f"{model} 200"
        # 状态码语义：401=key失效/端点错、402=欠费、403=额度尽、429=限流
        hint = ""
        body = r.text[:100].replace("\n", " ")
        if "invalid_iam_token" in body:
            hint = " ⚠️疑似base_url被污染打到错误端点!"
        return "FAIL", f"HTTP {r.status_code}{hint} {body[:70]}"
    except Exception as e:
        return "FAIL", str(e)[:70]


def check_providers() -> None:
    print("\n=== 1. LLM provider 可用性（真实 HTTP 探测）===")
    # P0 修复（2026-08-21）：赛前重置熔断状态，避免上轮残留熔断影响本轮
    try:
        from llm.client import reset_circuits
        reset_circuits()
    except Exception:
        pass

    # P0 修复（2026-08-21）：检查 base_url 残留污染——正式赛根因！
    # 但 client.py:530 已修复：显式 provider 时全局 BASE_URL 被忽略，不再污染。
    # 故此处按是否显式 provider 区分措辞，避免误报吓阻开赛。
    polluted = os.getenv("CTF_AGENT_LLM_BASE_URL", "").strip()
    explicit_provider = os.getenv("CTF_AGENT_LLM_PROVIDER", "").strip()
    if polluted:
        if explicit_provider:
            print(f"  [✓] CTF_AGENT_LLM_BASE_URL 已设 = {polluted[:45]}…")
            print(f"        显式 provider={explicit_provider} 已忽略全局 BASE_URL（P0 修复），不污染；网关仅作 auto 模式默认（合规）")
        else:
            print(f"  [i] CTF_AGENT_LLM_BASE_URL 已设 = {polluted[:45]}…（未显式 provider → 作为默认网关，合规）")
    else:
        print(f"  [✓] CTF_AGENT_LLM_BASE_URL 未设置（干净）")

    ok_count = 0
    fail_list = []
    for pname, label, keyenv in PROVIDERS:
        status, note = _probe_provider_http(pname)
        icon = {"OK": "✓", "NOKEY": "--", "FAIL": "✗", "NOLIVE": "--"}[status]
        print(f"  [{icon}] {label:12s} ({pname:12s}) {note}")
        if status == "OK":
            ok_count += 1
        elif status == "FAIL":
            fail_list.append(f"{pname}:{note}")
    print(f"  → 可用 {ok_count}/{len(PROVIDERS)}")
    if ok_count == 0:
        print("  [!!!] 0 个 provider 可用——禁止开赛！先排查 base_url 污染/欠费/额度")
    if fail_list:
        print(f"  失效清单: {'; '.join(fail_list[:5])}")


def check_platform() -> None:
    print("\n=== 2. 平台连通性 ===")
    from ctfplatform.dasctf import DasCTFPlatform

    p = DasCTFPlatform()
    if not p.base_url:
        print("  [✗] 未配置 DASCTF_BASE_URL")
        return
    if not p.token:
        print("  [✗] 未配置 accesskey（CTF_AGENT_PLATFORM_TOKEN）")
        return
    print(f"  平台: {p.base_url}（token 长度 {len(p.token)}）")
    try:
        chals = asyncio.run(p.list_challenges())
        print(f"  [✓] 连通 OK，当前题目 {len(chals)} 道（开赛后自动拉取）")
    except Exception as e:
        print(f"  [~] 连通但无题目权限（未开赛正常）: {str(e)[:60]}")

def check_regression() -> None:
    print("\n=== 3. 本地 3 题快速回归（主循环/工具/校验）===")
    from eval.cases import load_questions, preset_answers
    from run import build_solver

    qs = load_questions("data/questions")
    answers = preset_answers(qs)
    sel = [q for q in qs if q.id in ("crypto-006", "misc-004", "reverse-001")]
    if not sel:
        print("  [✗] 题库缺失，跳过")
        return
    solver = build_solver(use_mock=False, is_correct=lambda f: f in answers.values(),
                          provider="baidu")
    async def run():
        for q in sel:
            try:
                out = await solver(q, 0, None)
                ok = "✓" if out.get("flag") else "✗"
                print(f"  [{ok}] {q.id:12s} flag={out.get('flag') or '未解出'}")
            except Exception as e:
                print(f"  [✗] {q.id:12s} 异常: {str(e)[:60]}")
    asyncio.run(run())

def check_tooling() -> None:
    """工具/模板 100% 可用性实测（锐评「写过 vs 解出过」落地）。

    检查两类：
    1. 关键工具可导入（zipfile/zlib/capstone/py7zr/rarfile/sympy/Crypto/PIL 等）
    2. 实证确定性模板用内置样例真实跑通（caesar/b64/hash/morse/fermat——
       内置样例断言，非 LLM 依赖）——「解出过」不是「写过」
    """
    print("\n=== 6. 工具/模板 100% 可用性实测 ===")
    import importlib

    # ① 关键工具导入
    mods = ["zipfile", "zlib", "capstone", "py7zr", "rarfile",
            "sympy", "numpy", "Crypto", "PIL"]
    ok_mods = 0
    for m in mods:
        try:
            importlib.import_module(m)
            ok_mods += 1
        except ImportError:
            print(f"  [!!!] 工具缺失: {m}——对应 skill 全部不可用，禁止开赛！")
    print(f"  [{'✓' if ok_mods == len(mods) else '✗'}] 工具导入 {ok_mods}/{len(mods)}")
    if ok_mods != len(mods):
        print("  [!!!] 工具不全——先补依赖再开赛（pip install 缺失项）")

    # ③ bkcrack 二进制预检（2026-08-22 质检整改：zip 已知明文攻击唯一工具，
    #    exe 曾被系统 Temp 清理 + 中文路径执行失败——必须纯 ASCII 稳定路径）
    _bkcrack = None
    for _cand in (os.environ.get("BKCRACK", ""),
                  "C:/Users/Lenovo/bkcrack_161/bkcrack.exe",
                  "/usr/local/bin/bkcrack", "/usr/bin/bkcrack"):
        if _cand and os.path.isfile(_cand):
            _bkcrack = _cand
            break
    if _bkcrack:
        _ascii = _bkcrack.encode("ascii", errors="ignore").decode() == _bkcrack
        print(f"  [{'✓' if _ascii else '✗'}] bkcrack 可用: {_bkcrack}"
              + ("" if _ascii else "（⚠️ 含非 ASCII 路径，Windows cmd 下不可执行！）"))
        if not _ascii:
            print("  [!!!] bkcrack 必须放在纯 ASCII 路径（如 C:/Users/<name>/bkcrack_161/），"
                  "并设置环境变量 BKCRACK 指向 exe")
    else:
        print("  [!!!] bkcrack 未找到——zip 已知明文攻击不可用！")
        print("        下载 v1.6.1（1.7/1.8 此环境段错误）到纯 ASCII 路径，"
              "设置环境变量 BKCRACK；或 export PATH 包含 bkcrack 所在目录")

    # ② 实证模板自测（内置样例断言）
    import sys
    _skills = os.path.join(_ROOT, "skills")
    if _skills not in sys.path:
        sys.path.insert(0, _skills)
    cases = [
        ("caesar_bruteforce", "caesar", {"text": "synt{uvag_ebg13}"}, "flag{hint_rot13}"),
        ("base64_multilayer", "b64", {"text": "ZmxhZ3tiNjRfdGVzdH0="}, "flag{b64_test}"),
        ("hash_crack", "hash", {"hash": "21232f297a57a5a743894a0e4a801fc3", "hashtype": "md5"}, "admin"),
        ("morse_decoder", "morse", {"text": ".... . .-.. .-.. ---"}, "hello"),
        # 真实 RSA 费马样例（p=97,q=101 接近素数，费马分解适用；明文 42）
        ("rsa_fermat_factor", "fermat", {"n": 9797, "e": 65537, "c": 7123}, "b'*'"),
    ]
    ok_cases = 0
    for mod_name, label, params, expected in cases:
        try:
            mod = importlib.import_module(mod_name)
            r = mod.run(params) if hasattr(mod, "run") else None
            got = ""
            if isinstance(r, dict):
                got = str(r.get("flag") or r.get("plain") or r.get("result") or "")
            elif r:
                got = str(r)
            if expected is None:
                print(f"  [✓] {label:8s} 模块可导入（参数依赖跳过断言）")
                ok_cases += 1
            elif got and expected in got:
                print(f"  [✓] {label:8s} 自测解出: {got[:40]}")
                ok_cases += 1
            else:
                print(f"  [✗] {label:8s} 自测失败: got={got[:40]!r} expected={expected!r}")
        except Exception as e:
            print(f"  [✗] {label:8s} 模板不可用: {str(e)[:60]}")
    print(f"  [{'✓' if ok_cases == len(cases) else '✗'}] 实证模板自测 {ok_cases}/{len(cases)}")
    if ok_cases != len(cases):
        print("  [!!!] 有模板不可用——比赛路径禁用对应 skill（锐评：写过≠解出过）")

def check_report() -> None:
    print("\n=== 4. 解题报告生成路径 ===")
    try:
        from report.generator import generate_report, save_report
        md = generate_report(poller_records=[{
            "challenge_id": "smoke-test", "title": "链路自检", "category": "misc",
            "duration_s": 1.0, "flag": "", "accepted": False}])
        path = save_report(md, out_dir="data/reports/_preflight")
        print(f"  [✓] 报告生成 OK: {path}（{len(md)} 字符）")
    except Exception as e:
        print(f"  [✗] 报告生成失败: {str(e)[:80]}")

def check_env() -> None:
    print("\n=== 5. 环境自检（初赛 0 解出教训：环境残留是头号杀手）===")
    # 5.1 依赖：httpx 必须已装（赛前夜彩排 3/4 题空转根因）
    try:
        import httpx  # noqa: F401
        print(f"  [✓] httpx 已安装（{httpx.__version__}）")
    except ImportError:
        print("  [!!!] httpx 未安装——LLM 全链路不可用，禁止开赛！pip install httpx")

    # 5.2 残留环境变量：BASE_URL 在显式 provider 时已被 client.py 忽略（P0 修复），
    #     仅 auto 模式作默认网关；API_KEY 仍为全局覆盖风险（保留告警）
    explicit_provider = os.getenv("CTF_AGENT_LLM_PROVIDER", "").strip()
    v = os.getenv("CTF_AGENT_LLM_BASE_URL", "").strip()
    if v:
        if explicit_provider:
            print(f"  [✓] CTF_AGENT_LLM_BASE_URL 已设 = {v[:50]}……（显式 provider={explicit_provider} 已忽略全局 BASE_URL，不污染；网关仅作 auto 默认）")
        else:
            print(f"  [i] CTF_AGENT_LLM_BASE_URL 已设 = {v[:50]}……（未显式 provider → 默认网关，合规）")
    else:
        print(f"  [✓] CTF_AGENT_LLM_BASE_URL 未设置（干净）")
    v = os.getenv("CTF_AGENT_LLM_API_KEY", "").strip()
    if v:
        print(f"  [!!!] CTF_AGENT_LLM_API_KEY 已设置 = {v[:50]}…… → 覆盖所有 provider key，残留=非目标 key 401！须置空")
    else:
        print(f"  [✓] CTF_AGENT_LLM_API_KEY 未设置（干净）")

    # 5.3 残留 race 进程：多进程并发互踩 solved/attempts 锁（初赛 5 进程互踩教训）
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*_race_start*' -and $_.Name -eq 'python.exe' }).Count"],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        n = int(out) if out.isdigit() else 0
        if n:
            print(f"  [!!!] 检测到 {n} 个残留 _race_start 进程——须先杀掉再开赛！")
        else:
            print("  [✓] 无残留 _race_start 进程")
    except Exception:
        print("  [~] 残留进程检查跳过（非 Windows 或权限不足）")

    # 5.4 并发数合规（靶机槽位 3 + 跨题并发）
    conc = os.getenv("CTF_AGENT_MAX_CONCURRENCY", "2")
    print(f"  [✓] CTF_AGENT_MAX_CONCURRENCY = {conc}（建议 2-3，过高触发平台限流）")

    # 5.5 合规环境变量
    enforce = os.getenv("CTF_AGENT_ENFORCE_WHITELIST", "0")
    human = os.getenv("CTF_AGENT_ALLOW_HUMAN", "")
    print(f"  CTF_AGENT_ENFORCE_WHITELIST = {enforce or '0'}（初赛建议 1，白名单强制）")
    print(f"  CTF_AGENT_ALLOW_HUMAN = {human or '(未设置✓ 人工干预禁用=合规)'}")
    print(f"  CTF_AGENT_LLM_PROVIDER = {os.getenv('CTF_AGENT_LLM_PROVIDER', '(未设，用 build_race_solver 竞速)')}")

def check_dryrun() -> None:
    """全链路 dry-run（初赛 0 解出教训：赛前必须真实跑通 拉题→解 1 题→断言）。

    设计：
    1. 平台可用时拉真实题；平台无题(未开赛/已关闭)时回退本地 real 真题
    2. 用真实 LLM solver 解 1 题(非 mock)
    3. 断言：解出 flag 且非空 → PASS；否则 FAIL 阻止开赛
    """
    print("\n=== 6. 全链路 dry-run（拉题→真实解 1 题→断言）===")
    from eval.cases import load_questions, preset_answers
    from run import build_solver

    # ① 拉题：平台优先，失败回退本地
    question = None
    source = ""
    try:
        from ctfplatform.dasctf import DasCTFPlatform
        p = DasCTFPlatform()
        chals = asyncio.run(p.list_challenges())
        unsolved = [c for c in chals if not (c.extra or {}).get("hasSolved")]
        if unsolved:
            import json as _json
            # ChallengeInfo → Question 简化转换（id/category/title/description/attachments）
            c0 = unsolved[0]
            question = type("Q", (), {
                "id": c0.id, "category": c0.category, "title": c0.title,
                "description": c0.description or "", "attachments": [],
                "extra": c0.extra or {},
            })()
            source = f"平台题 {c0.id} {c0.title[:20]}"
    except Exception as exc:  # noqa: BLE001 - 平台不可用回退本地
        print(f"  [~] 平台拉题失败({str(exc)[:50]})，回退本地真题")

    if question is None:
        qs = load_questions("data/questions", include_disclosed=False)
        # 优先确定性 crypto 真题（附件在本地、工具链成熟、不依赖靶机）
        for q in qs:
            if q.id in ("real_crypto_ezmult", "real_crypto_caesar", "real_crypto_hash_brute",
                        "crypto-006", "crypto-002", "crypto-003"):
                if any(os.path.exists(a) for a in q.attachments):
                    question, source = q, f"本地真题 {q.id} {q.title[:20]}"
                    break
    if question is None:
        print("  [✗] 无可用题目(平台未开+本地真题缺失)——dry-run 无法执行")
        return

    print(f"  [i] 选定: {source}")
    answers = preset_answers(load_questions("data/questions"))
    provider = os.getenv("CTF_AGENT_LLM_PROVIDER", "").strip() or None
    solver = build_solver(use_mock=False, is_correct=lambda f: f in answers.values(),
                          provider=provider)

    async def _run():
        try:
            out = await solver(question, 0, None)
            return out
        except Exception as exc:  # noqa: BLE001
            return {"flag": None, "error": str(exc)[:120]}

    out = asyncio.run(_run())
    flag = out.get("flag")
    error = out.get("error") or out.get("detail") or ""
    if flag:
        print(f"  [✓] dry-run 解出 flag: {flag}")
        print("  [✓] 全链路 PASS——拉题/LLM/工具/校验全部真实可用，可以开赛")
    else:
        print(f"  [✗] dry-run 未解出（{error or '未知'}）")
        print("  [!!!] LLM 链路/工具链存在问题——先修好再开赛，勿重蹈初赛覆辙！")

def clean_test_data() -> None:
    print("\n=== 0. 清理测试数据 ===")
    import glob
    removed = 0
    for pat in ["data/results/benchmark_after_postmortem*.json",
                "data/reports/解题报告_*.md",
                "data/reports/_preflight/*"]:
        for f in glob.glob(pat):
            try:
                os.remove(f)
                removed += 1
            except OSError:
                pass
    print(f"  已清理 {removed} 个测试文件（benchmark/报告）")

def main() -> None:
    ap = argparse.ArgumentParser(description="赛前 10 分钟检查清单")
    ap.add_argument("--clean", action="store_true", help="先清理测试数据再检查")
    ap.add_argument("--skip-regression", action="store_true", help="跳过本地回归（省时）")
    args = ap.parse_args()

    if args.clean:
        clean_test_data()
    check_providers()
    check_platform()
    if not args.skip_regression:
        check_regression()
    check_dryrun()
    check_tooling()
    check_report()
    check_env()
    print("\n=== ✅ 赛前检查完成 ===")

if __name__ == "__main__":
    main()
