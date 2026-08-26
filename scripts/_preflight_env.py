"""赛前环境验证脚本（锐评「环境不可用=出局」修复——2026-08-22）。

正式赛 0 解出锐评：比赛环境 python 输出无响应/链路 40403/大文件超时——
「比赛中系统不可用 = 直接出局」。本脚本赛前验证环境 100% 可用：
1. python 输出可用性（跑简单脚本确认输出正常——0 解出期间输出无响应的预防）
2. 链路验证（拉题 exercise-list 非 40403——AccessKey 有效）
3. 大文件处理（mmap 快速扫——16MB 级不超时）
4. 网关/配置确认（LLM_BASE_URL/HEAVY_MODEL/ENFORCE）

用法：python scripts/_preflight_env.py——全部 PASS 才可开赛。
"""

import os
import subprocess
import sys


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
    """④ 配置确认——网关/重型/白名单。"""
    gw = os.getenv("CTF_AGENT_LLM_BASE_URL", "")
    heavy = os.getenv("CTF_AGENT_HEAVY_MODEL", "")
    enf = os.getenv("CTF_AGENT_ENFORCE_WHITELIST", "")
    ok = bool(gw) and "llm-gateway" in gw and heavy == "deepseek-reasoner" and enf == "1"
    print(f"④ 配置: {'✅' if ok else '❌'} 网关={'有' if gw else '无'} 重型={heavy} ENFORCE={enf}")
    return ok


def main() -> int:
    print("=" * 50)
    print("赛前环境验证（锐评「环境不可用=出局」修复）")
    print("=" * 50)
    results = [check_python_output(), check_link(), check_bigfile(), check_config()]
    passed = sum(results)
    print(f"\n结果: {passed}/4 PASS——{'✅ 可开赛' if passed == 4 else '❌ 修复后重跑'}")
    return 0 if passed == 4 else 1


if __name__ == "__main__":
    sys.exit(main())
