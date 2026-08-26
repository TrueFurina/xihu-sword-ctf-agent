"""数学引擎矩阵（2026-08-21 攻坚）：确定性求解器统一入口。

架构定位：与 LLM 矩阵（多模型并发写攻击代码）并行竞争——
LLM 负责"识别题型+写代码"，数学引擎负责"确定性秒解"。
两者同时开跑，任一先得有效 flag 即胜（双矩阵竞速）。

本模块把所有确定性求解器注册为统一接口：
    MathEngineMatrix.solve(question) -> (engine_name, flag_or_None)

引擎清单（按题型路由）：
- crypto 编码/古典：base64 多层/凯撒/维吉尼亚/摩斯
- crypto RSA 系：fermat/small_e/wiener/common_modulus/hastad/phi_known/phi_known_inv
- crypto 特殊：二次剩余(legendre)/噪声LFSR(filterrandom)/格攻击/ECB/coppersmith
- reverse 静态：UPX/字符串/分离串（flag + {xxx}）
- misc 取证：zip链/伪加密/磁盘/流量

设计原则：
1. 所有引擎确定性（同一输入必同输出），无 LLM 参与
2. 失败返回 None，绝不抛异常（竞速容错）
3. 秒级优先（先跑快引擎，慢引擎如 ECM 分解设超时）
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)


class MathEngineMatrix:
    """确定性数学引擎矩阵：按题型/附件特征路由到具体求解器。"""

    # ── 引擎注册表：name -> callable(question) -> Optional[str] ──
    _engines: dict = {}

    @classmethod
    def register(cls, name: str):
        """装饰器：注册引擎。"""

        def deco(fn):
            cls._engines[name] = fn
            return fn

        return deco

    @classmethod
    def names(cls) -> list:
        return list(cls._engines.keys())

    @classmethod
    def solve(cls, question, timeout: float = 60.0) -> tuple:
        """按顺序尝试全部引擎，返回 (engine_name, flag)。

        Args:
            question: Question 对象（attachments 必须指向真实文件）
            timeout: 单引擎超时秒（慢引擎跳过）

        Returns:
            (engine_name, flag) 或 (None, None)
        """
        # 快引擎优先：编码/静态/RSA 变种秒级，慢引擎（ECM/DLP）最后
        # P1-2 修复（2026-08-21 赛后）：总时间预算——到点即停止启动新引擎，
        # 避免"事后检查 dt"导致慢引擎阻塞整个矩阵数分钟。
        _deadline = time.monotonic() + timeout
        for name in cls._priority_order():
            fn = cls._engines.get(name)
            if not fn:
                continue
            if time.monotonic() >= _deadline:
                logger.info("[math_engine] 总时间预算耗尽（>%.0fs），跳过剩余引擎", timeout)
                break
            t0 = time.time()
            try:
                flag = fn(question)
            except Exception as exc:  # noqa: BLE001 - 单引擎失败不拖垮矩阵
                logger.debug("[math_engine:%s] 异常: %s", name, exc)
                flag = None
            dt = time.time() - t0
            if flag:
                logger.info("[math_engine:%s] 命中 %s (%.1fs)",
                            name, getattr(question, "id", "?"), dt)
                return (name, str(flag))
            if dt > timeout:
                logger.info("[math_engine:%s] 超时跳过 (%.1fs)", name, dt)
        return (None, None)

    @classmethod
    def _priority_order(cls) -> list:
        """引擎优先级：快/确定性高优先。

        空壳引擎（coppersmith/lattice/ecb/ecm/dlp/vigenere 本机无 Sage/oracle）
        不列入竞速顺序——避免无意义遍历拖慢秒解路径（锐评 P1-3）。
        legendre 引擎与 rsa_chain 完全重复（都跑 build_fallback_script，其 _TRIAGE_BODY
        已含 SimpleLegendre 二次剩余嗅探）——2026-08-21 实战扫描发现每 crypto 附件
        重复跑 2 次 fallback，剔除 legendre 提速一倍。
        决赛S2（2026-08-21）：追加 3 个真题 skill 引擎（crypto_pkcs1_oracle /
        crypto_high_exponent / misc_bigfile_lime）——这些 skill 已沉淀但此前未进
        math_engine 竞速，32 题 dry-run 实测 0% 命中；接线后由 presolve 链路一
        次性完成"嗅探→攻击→出 flag"。
        """
        return [
            "crypto_multilayer", "crypto_caesar", "crypto_morse", "crypto_vigenere",
            "rsa_chain", "lfsr", "reverse_static",
            "crypto_pkcs1_oracle", "crypto_high_exponent",
            "web_source_audit_cms",
            "misc_decode", "misc_zip", "misc_bigfile_lime",
        ]


# ── 引擎实现 ──────────────────────────────────────────


def _run_async(coro):
    """循环安全的 async 调用：已有事件循环用 run_until_complete，否则 asyncio.run。

    竞速场景 math_engine 在 race() 的 async 函数内被调用，asyncio.run 会
    报 "coroutine never awaited"（2026-08-21 双矩阵接入时实测）。
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # 已有循环：新建任务并等待（线程安全；subprocess 场景 OK）
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _attach_texts(question) -> str:
    """拼接全部附件文本（多附件完整性）。"""
    parts = []
    for p in (getattr(question, "attachments", None) or []):
        try:
            with open(str(p), "rb") as f:
                parts.append(f.read().decode("utf-8", errors="ignore"))
        except OSError:
            pass
    return "\n".join(parts)


@MathEngineMatrix.register("crypto_multilayer")
def _engine_multilayer(question):
    """多层编码解码（base64/hex/url + ROT13 收尾）——ezmult 类。"""
    if getattr(question, "category", "") != "crypto":
        return None
    text = _attach_texts(question)
    if not text:
        return None
    # 找 base64/hex 长串
    import re
    import base64
    for m in re.finditer(r"[A-Za-z0-9+/=]{24,}", text):
        token = m.group(0)
        try:
            b = base64.b64decode(token)
            s = b.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if s.startswith("synt{"):  # ROT13 的 flag{
            out = "".join(
                chr((ord(c) - ord("a") + 13) % 26 + ord("a")) if "a" <= c <= "z"
                else (chr((ord(c) - ord("A") + 13) % 26 + ord("A")) if "A" <= c <= "Z" else c)
                for c in s
            )
            import re as _re
            if _re.search(r"(?i)(?:flag|ctf|dasctf)\{", out):
                return out
        # 多层解码兜底，直接用 _inline_multilayer_decode 处理所有候选
        from agents.crypto_toolkit import _inline_multilayer_decode
        decoded = _inline_multilayer_decode(token)
        _m = __import__("re").search(r"(?i)(?:flag|ctf|dasctf)\{[^}\s]+\}", decoded)
        if _m:
            return _m.group(0)
    return None


@MathEngineMatrix.register("crypto_caesar")
def _engine_caesar(question):
    """凯撒 26 位移爆破。"""
    if getattr(question, "category", "") != "crypto":
        return None
    text = _attach_texts(question)
    for line in text.splitlines():
        s = line.strip()
        # 纯字母或含 { 的候选
        for shift in range(26):
            pt = "".join(
                chr((ord(c) - 97 + shift) % 26 + 97) if "a" <= c <= "z"
                else (chr((ord(c) - 65 + shift) % 26 + 65) if "A" <= c <= "Z" else c)
                for c in s
            )
            if re.search(r"(?i)(?:flag|ctf|dasctf)\{", pt):
                import re as _re_m
                _fm = _re_m.search(r"(?i)(?:flag|ctf|dasctf)\{[^}\s]+\}", pt)
                if _fm:
                    return _fm.group(0)
    return None


@MathEngineMatrix.register("crypto_vigenere")
def _engine_vigenere(question):
    """维吉尼亚解码（2022安网杯 crypto1 模式：八进制/hex/base64 + key:data）。

    2026-08-22 M3：从空壳改为委托 skills.vigenere_decode（完整实现
    已沉淀但从未接线——又一处沉睡 skill）。附件为文本时直接调 skill run()。
    """
    if getattr(question, "category", "") != "crypto":
        return None
    try:
        import re
        from skills.vigenere_decode import run as vig_run
        atts = list(getattr(question, "attachments", None) or [])
        for a in atts:
            if not os.path.isfile(str(a)):
                continue
            r = vig_run({"path": str(a)})
            fc = r.get("flag_candidate") if isinstance(r, dict) else ""
            if fc and re.search(r"(?:flag|DASCTF|ctf)\{[^}\s]+\}", fc, re.I):
                return fc
    except Exception as exc:  # noqa: BLE001
        logger.debug("[vigenere] %s", exc)
    return None


@MathEngineMatrix.register("crypto_morse")
def _engine_morse(question):
    """摩斯码解码。"""
    if getattr(question, "category", "") != "crypto":
        return None
    text = _attach_texts(question)
    MORSE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z",
    }
    for line in text.splitlines():
        if re_match := __import__("re").fullmatch(r"[.\- ]+", line.strip()):
            words = line.strip().split("  ")
            out = ""
            for w in words:
                for c in w.split():
                    out += MORSE.get(c, "")
                out += " "
            import re as _re_mo
            if _re_mo.search(r"(?i)(?:flag|ctf|dasctf)\{", out):
                _fm = _re_mo.search(r"(?i)(?:flag|ctf|dasctf)\{[^}\s]+\}", out)
                if _fm:
                    return _fm.group(0)
                return out.strip()
    return None


@MathEngineMatrix.register("rsa_chain")
def _engine_rsa(question):
    """RSA 全套确定性攻击（fermat/small_e/wiener/common_modulus/hastad/phi_known/phi_known_inv）。

    直接委托 CryptoToolkit 的兜底脚本（沙盒内执行，覆盖裸数字行/参数行/多附件）。
    """
    if getattr(question, "category", "") != "crypto":
        return None
    try:
        from agents.crypto_toolkit import CryptoToolkit
        import asyncio
        from sandbox.subprocess_executor import SubprocessExecutor

        atts = list(getattr(question, "attachments", None) or [])
        if not atts:
            return None
        # P1 修复（2026-08-21 实战扫描）：zip/图片/pcap 等二进制附件不应进文本嗅探
        # ——decode 成乱码后 _TRIAGE_BODY 对乱码做无意义计算（实测 600s 卡死拖死并发池）。
        # 二进制附件交给 misc_zip/misc_decode 引擎，此处只保留文本附件。
        _BIN_EXTS = (".zip", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".pcap",
                     ".pcapng", ".exe", ".elf", ".so", ".bin", ".pdf", ".docx",
                     ".rar", ".tar", ".gz", ".pyc")
        _text_atts = [a for a in atts if not str(a).lower().endswith(_BIN_EXTS)]
        if not _text_atts:
            return None
        script = CryptoToolkit.build_fallback_script(str(_text_atts[0]), extra_paths=_text_atts[1:])
        if not script:
            return None
        sb = SubprocessExecutor(default_timeout=30)
        result = _run_async(sb.run(f"python: {script}"))
        out = str(result.stdout)
        import re
        m = re.search(r"(?:flag|DASCTF|ctf)\{[^}\s]+\}", out, re.I)
        return m.group(0) if m else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("[rsa_chain] %s", exc)
        return None


@MathEngineMatrix.register("legendre")
def _engine_legendre(question):
    """二次剩余逐位加密（SimpleLegendre 类）。"""
    if getattr(question, "category", "") != "crypto":
        return None
    try:
        from agents.crypto_toolkit import CryptoToolkit
        import asyncio
        from sandbox.subprocess_executor import SubprocessExecutor

        atts = list(getattr(question, "attachments", None) or [])
        if not atts:
            return None
        # P1 修复（2026-08-21 实战扫描）：zip/图片/pcap 等二进制附件不应进文本嗅探
        # ——decode 成乱码后 _TRIAGE_BODY 对乱码做无意义计算（实测 600s 卡死拖死并发池）。
        # 二进制附件交给 misc_zip/misc_decode 引擎，此处只保留文本附件。
        _BIN_EXTS = (".zip", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".pcap",
                     ".pcapng", ".exe", ".elf", ".so", ".bin", ".pdf", ".docx",
                     ".rar", ".tar", ".gz", ".pyc")
        _text_atts = [a for a in atts if not str(a).lower().endswith(_BIN_EXTS)]
        if not _text_atts:
            return None
        script = CryptoToolkit.build_fallback_script(str(_text_atts[0]), extra_paths=_text_atts[1:])
        if not script:
            return None
        sb = SubprocessExecutor(default_timeout=30)
        result = _run_async(sb.run(f"python: {script}"))
        out = str(result.stdout)
        import re
        m = re.search(r"(?:flag|DASCTF|ctf)\{[^}\s]+\}", out, re.I)
        return m.group(0) if m else None
    except Exception:  # noqa: BLE001
        return None


@MathEngineMatrix.register("lfsr")
def _engine_lfsr(question):
    """噪声混合 LFSR（FilterRandom 类）。"""
    if getattr(question, "category", "") != "crypto":
        return None
    try:
        from skills.lfsr_filter_recover import solve_lfsr_filter
        text = _attach_texts(question)
        import re
        # 2026-08-22 M3 修复：附件末尾常带 `'''` 注释包裹，
        # 严格 `^数字$` 整行匹配失败——放宽为"长串中抓 0/1 段"
        masks = [int(x) for x in re.findall(r"(?<!\d)(\d{17,22})(?!\d)", text)]
        bit_strs = re.findall(r"[01]{1000,}", text)
        if len(masks) >= 2 and bit_strs:
            flag = solve_lfsr_filter(masks[0], masks[1], bit_strs[0])
            return flag if flag else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("[lfsr] %s", exc)
    return None


@MathEngineMatrix.register("reverse_static")
def _engine_reverse(question):
    """reverse 静态分析（UPX/字符串/分离串）。"""
    if getattr(question, "category", "") not in ("reverse", "pwn"):
        return None
    try:
        from core.fallbacks import build_reverse_fallback_script
        import asyncio
        from sandbox.subprocess_executor import SubprocessExecutor

        atts = list(getattr(question, "attachments", None) or [])
        if not atts:
            return None
        # 构造临时 ctx（fallbacks 需要 ctx 鸭子类型）
        from eval.cases import Question
        from core.main_agent import AgentContext

        q = Question(id="tmp", title="t", category="reverse", description="",
                     attachments=atts)
        ctx = AgentContext(question=q)
        ctx._attachment_analyzed = True
        script = build_reverse_fallback_script(ctx)
        if not script:
            return None
        sb = SubprocessExecutor(default_timeout=60)
        result = _run_async(sb.run(f"python: {script}"))
        out = str(result.stdout)
        import re
        m = re.search(r"(?:flag|DASCTF|ctf)\{[^}\s]+\}", out, re.I)
        return m.group(0) if m else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("[reverse_static] %s", exc)
        return None


@MathEngineMatrix.register("misc_zip")
def _engine_misc_zip(question):
    """misc zip 链/伪加密/文件名链解码（调用已有 skill，确定性）。"""
    if getattr(question, "category", "") != "misc":
        return None
    atts = list(getattr(question, "attachments", None) or [])
    if not atts:
        return None
    import os
    # 找第一个 zip 附件
    zip_path = None
    for a in atts:
        p = str(a)
        if p.lower().endswith((".zip", ".7z")) or os.path.isfile(p) and _is_zip(p):
            zip_path = p
            break
    if not zip_path:
        return None
    try:
        # 1) 文件名链解码 skill
        from skills.zip_filename_chain_decode import zip_filename_chain_decode
        res = zip_filename_chain_decode({"zip_path": zip_path, "max_layers": 100})
        if res and res.get("flag"):
            return res["flag"]
    except Exception as exc:  # noqa: BLE001
        logger.debug("[misc_zip] skill: %s", exc)
    try:
        # 2) 直接递归解 zip（无密码/常见密码），搜索 flag 文本
        # P1-2 修复（2026-08-21 赛后）：整段给 20s 时间预算——zip 5 位爆破
        # × 多层套娃实测可阻塞数分钟（to_thread 无法取消），必须硬性到点退出。
        import io, zipfile
        _t_budget = 20.0
        _t_start = time.monotonic()
        zdata = open(zip_path, "rb").read()
        found = _recurse_zip(zdata, depth=0, time_budget=_t_budget, t_start=_t_start)
        if found:
            return found
    except Exception as exc:  # noqa: BLE001
        logger.debug("[misc_zip] recurse: %s", exc)
    return None


@MathEngineMatrix.register("misc_decode")
def _engine_misc_decode(question):
    """misc 文本类多策略解码（base64/hex/url/morse/ROT13/DNS/zip链）。

    委托 deterministic_decode 适配器（多策略链式，确定性）。
    """
    if getattr(question, "category", "") != "misc":
        return None
    try:
        from tools.adapters.deterministic_decode_adapter import DeterministicDecodeAdapter
        import asyncio

        adapter = DeterministicDecodeAdapter()
        # 优先读附件文本
        text = _attach_texts(question)
        params = {"text": text, "strategy": "auto"}
        # 附件是纯文本时直接解码；否则也试 path
        atts = list(getattr(question, "attachments", None) or [])
        if atts and not text.strip():
            params["path"] = str(atts[0])
        out = _run_async(adapter.run(params))
        if out and getattr(out, "ok", False):
            import re
            m = re.search(r"(?:flag|DASCTF|ctf)\{[^}\s]{3,}\}", str(out.text), re.I)
            if m:
                return m.group(0)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[misc_decode] %s", exc)
    return None


def _is_zip(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def _recurse_zip(zdata: bytes, depth: int, time_budget: float = 20.0,
                 t_start: float | None = None) -> Optional[str]:
    """递归解 zip（无密码/常见弱密码），搜索 flag 文本或继续套娃。

    P1-2 修复（2026-08-21 赛后）：time_budget 总时间预算——递归/爆破到点
    即返回 None，避免多层 zip 套娃（每层 5 位爆破 ~2.8s × 多层）阻塞矩阵。
    """
    if depth > 50:
        return None
    t_start = t_start if t_start is not None else time.monotonic()
    if time.monotonic() - t_start >= time_budget:
        logger.info("[misc_zip] 递归时间预算耗尽（%.0fs），放弃", time_budget)
        return None
    import io, zipfile, re
    try:
        z = zipfile.ZipFile(io.BytesIO(zdata))
        for info in z.infolist():
            if time.monotonic() - t_start >= time_budget:
                logger.info("[misc_zip] 递归时间预算耗尽（%.0fs），放弃", time_budget)
                return None
            enc = bool(info.flag_bits & 0x1)
            if enc:
                # P1 修复（2026-08-21 实战演练）：加密层 5 位数字爆破（常见 CTF
                # zip 题密码，实测 zipfile 爆破 ~23000 密码/s，2.8s 破一层）。
                # 捕获所有解压异常（zlib.error 假阳性：1/256 密码过 check byte
                # 但解压失败，会误当作命中——必须吞掉继续爆破）。
                content = _brute_5digit(z, info.filename, time_budget, t_start)
                if content is None:
                    continue
            else:
                try:
                    content = z.read(info.filename)
                except Exception:
                    continue
            name = info.filename.lower()
            if name.endswith((".zip", ".7z")):
                inner = _recurse_zip(content, depth + 1, time_budget, t_start)
                if inner:
                    return inner
            else:
                try:
                    txt = content.decode("utf-8", errors="ignore")
                except Exception:
                    txt = ""
                m = re.search(r"(?:flag|DASCTF|ctf)\{[^}\s]{3,}\}", txt, re.I)
                if m:
                    return m.group(0)
                # 二进制里也可能有 flag 文本
                m2 = re.search(rb"(?:flag|DASCTF|ctf)\{[^}\s]{3,}\}", content, re.I)
                if m2:
                    return m2.group(0).decode()
    except Exception:
        return None
    return None


def _brute_5digit(zf, name: str, time_budget: float = 20.0,
                  t_start: float | None = None) -> Optional[bytes]:
    """5 位数字爆破加密 zip 成员，返回解出的内容（失败 None）。

    捕获所有异常（RuntimeError=错密码 / zlib.error=假阳性 check byte 过检 /
    BadZipFile=CRC 错），任何异常都视为"该密码不对"继续爆破。
    P1-2 修复（2026-08-21 赛后）：time_budget 到点即放弃，防止慢分支
    拖死整个矩阵（to_thread 无法取消，只能内部硬超时）。
    """
    t_start = t_start if t_start is not None else time.monotonic()
    for i in range(100000):
        if i % 5000 == 0 and time.monotonic() - t_start >= time_budget:
            logger.info("[misc_zip] 5 位爆破时间预算耗尽（%.0fs），放弃", time_budget)
            return None
        pwd = f"{i:05d}".encode()
        try:
            return zf.read(name, pwd=pwd)
        except Exception:
            pass
    return None


@MathEngineMatrix.register("crypto_coppersmith")
def _engine_coppersmith(question):
    """Coppersmith 小根（部分私钥等）。"""
    return None  # 需要 sage/fplll，本机无，留给 LLM


@MathEngineMatrix.register("crypto_lattice")
def _engine_lattice(question):
    """格攻击（LLL）。"""
    return None  # 需要 fpylll，本机无，留给 LLM


@MathEngineMatrix.register("crypto_ecb")
def _engine_ecb(question):
    """AES-ECB 块攻击。"""
    return None  # 需要交互式 oracle，留给 LLM


@MathEngineMatrix.register("rsa_factor_ecm")
def _engine_ecm(question):
    """ECM 分解 n（慢引擎，60s 超时）。"""
    return None  # 慢，赛中按需启用


@MathEngineMatrix.register("dlp_bsgs")
def _engine_dlp(question):
    """DLP（慢引擎，跳过——需 Sage/index calculus）。"""
    return None  # 本机无 Sage，跳过（赛中操作员用 SageCell 手动解）


# ── 决赛 S2 接入（2026-08-21）：3 个真题 skill 引擎 ──────────────
# 这些 skill 早已沉淀在 skills/ 下，决赛前未接 math_engine → 32 题 dry-run
# 实测 0% 命中。接线后由 presolve → math_engine 统一嗅探出 flag。

@MathEngineMatrix.register("crypto_pkcs1_oracle")
def _engine_pkcs1_oracle(question):
    """PKCS#1 v1.5 低指数 + AES-ECB 解 PDF 真题链（10732 验证）。

    嗅探特征：附件为 .py，含 `p = getPrime`、`n = p*q*r|p*q`、
    `hint_enc = pow(`、`PKCS#1.v1.5.enc` 任意组合 → 解析任务源码抽取
    padded_long / p / n / enc_file，调用 crypto_pkcs1_padding_oracle.skill
    full 链；PDF 解出后 pymupdf 文本层搜 flag（部分题目视觉渲染层才有，
    文本提取 miss，落到兜底）。
    """
    import re

    if getattr(question, "category", "") != "crypto":
        return None
    atts = [a for a in (getattr(question, "attachments", None) or [])
            if str(a).lower().endswith(".py") and __import__("os").path.exists(str(a))]
    if not atts:
        return None
    try:
        # 找 task.py 主文件
        main_path = next((a for a in atts if "task" in str(a).lower() or "main" in str(a).lower()),
                         atts[0])
        with open(main_path, encoding="utf-8", errors="ignore") as f:
            src = f.read()[:200_000]
    except Exception:
        return None
    # 必须含 PKCS#1 v1.5 标志
    if "PKCS1_v1_5" not in src and "PKCS#1.v1.5" not in src and "PKCS#1 v1.5" not in src:
        return None
    # 抽 padded_long：常见形态 `print(pow(bytes_to_long(AES_KEY_ENC),d,q*r))`
    # 注意：q*r 是表达式，正则不能用 [A-Za-z_]+ 硬性要求单变量名。
    # 改用 str.find 定位 + 注释块大整数提取。
    # 任务源码（task.py）注释块典型结构（10732 实测）：
    #   # My gift for you: <p>          ← 309 位
    #   # hint_enc: <hint_enc>           ← 309 位
    #   # n: <n>                         ← 925 位（3 个 1024 bit 素数乘积）
    #   # AES_KEY_ENC: <AES_KEY_ENC>     ← 616 位（2048 bit 整数）
    #   # <padded_long>                  ← 612 位（无 label 注释，最后一行）
    # 选规则：注释行 `# ` 后无 `<word>:` label 且含 200+ 位整数的，取最后一个。
    # 兜底：直接挑 bit_length 最接近 2040（padded_long 255B ≈ 2040 bit）且 ≤ 2048 的整数。
    padded_long = None
    idx = src.find("print(pow(bytes_to_long")
    if idx < 0:
        idx = src.find("print (pow (bytes_to_long")
    if idx >= 0:
        tail = src[idx:idx + 20_000]
        # 抽所有 200+ 位整数
        all_ints = [(int(x), m.start()) for m in
                    re.finditer(r"(?<!\d)(\d{200,})", tail)]
        # 优先 1) 无 label 的 600+ 位数字；2) 200+ 位数字中 bit_length 接近 2040 的
        unlabeled = []
        for v, off in all_ints:
            # 取该整数所在行
            line_start = tail.rfind("\n", 0, off) + 1
            line_end = tail.find("\n", off)
            if line_end < 0:
                line_end = len(tail)
            line = tail[line_start:line_end]
            # 注释行 + 数字前无 `word:` label
            if line.lstrip().startswith("#"):
                rest = line.lstrip()[1:].lstrip()
                # 有 `word: <num>` 形式视为 labeled
                if ":" not in rest.split(str(v), 1)[0]:
                    unlabeled.append(v)
        if unlabeled:
            padded_long = unlabeled[-1]  # 最后一个无 label 注释
        if padded_long is None:
            # 兜底：bit_length 最接近 2040 的 200+ 位整数
            for v, _ in all_ints:
                if 1900 <= v.bit_length() <= 2100:
                    padded_long = v
                    break
        if padded_long is None and all_ints:
            # 再兜底：最大整数
            padded_long = max(v for v, _ in all_ints)
    if padded_long is None:
        return None
    # 找 .enc 文件（题目附件内或 .py 引用）
    enc_path = ""
    atts_all = list(getattr(question, "attachments", None) or [])
    for a in atts_all:
        if str(a).lower().endswith(".enc"):
            enc_path = str(a)
            break
    if not enc_path:
        m = re.search(r"open\s*\(\s*[\"']([^\"']+\.enc)[\"']", src)
        if m:
            cand = m.group(1).split("/")[-1].split("\\")[-1]
            for a in atts_all:
                if cand in str(a):
                    enc_path = str(a)
                    break
    if not enc_path or not __import__("os").path.exists(enc_path):
        return None
    try:
        from skills.crypto_pkcs1_padding_oracle import crypto_pkcs1_padding_oracle
        res = crypto_pkcs1_padding_oracle({
            "kind": "full",
            "padded_long": padded_long,
            "msg_len": 16,
            "enc_file": enc_path,
        })
    except Exception as exc:  # noqa: BLE001
        logger.debug("[crypto_pkcs1_oracle] skill 异常: %s", exc)
        return None
    if not res.get("ok"):
        return None
    # PDF 文本层 + 视觉渲染层抓 flag
    out_file = res["steps"]["aes_ecb"].get("out_file")
    pt = res["steps"]["aes_ecb"].get("plaintext", b"")
    flag = _extract_flag_from_bytes(pt)
    if flag:
        return flag
    if out_file and __import__("os").path.exists(out_file):
        # 先试 pymupdf 文本层
        flag = _extract_flag_from_pdf_text(out_file)
        if flag:
            return flag
    return None


@MathEngineMatrix.register("crypto_high_exponent")
def _engine_high_exponent(question):
    """高偶指数 RSA 攻击（e=65536=2^16 真题场景，10733 验证）。

    嗅探特征：附件 .py 含 `e = 65536` 或 `e = 2**16`，且
    `hint = pow(...` 与 `c = pow(m, e, n)` 共现。抽取 hint/c/n 调
    crypto_high_exponent.skill auto 链（auto 内部先 factor_from_hint
    再 odd-subgroup/Rabin），返回的 flag 含 rot13/rot18 候选时优先 rot18。
    """
    import re

    if getattr(question, "category", "") != "crypto":
        return None
    atts = [a for a in (getattr(question, "attachments", None) or [])
            if str(a).lower().endswith(".py") and __import__("os").path.exists(str(a))]
    if not atts:
        return None
    try:
        main_path = next((a for a in atts if "task" in str(a).lower() or "main" in str(a).lower()),
                         atts[0])
        with open(main_path, encoding="utf-8", errors="ignore") as f:
            src = f.read()[:200_000]
    except Exception:
        return None
    # 高偶指数特征
    if not re.search(r"e\s*=\s*(?:65536|2\s*\*\*\s*16|2\s*\^\s*16|0x10000)", src):
        return None
    if "hint" not in src or "pow(m" not in src and "pow(flag" not in src and "pow(bytes_to_long" not in src:
        return None
    # 抽 hint / c / n（按出现顺序的整数字面量）
    nums = []
    for ln in src.splitlines():
        s = ln.strip()
        m = re.match(r"^(?:hint|c|n)\s*=\s*(-?\d{40,})", s)
        if m:
            nums.append((s.split("=")[0].strip(), int(m.group(1))))
    d = {k: v for k, v in nums}
    if not ({"hint", "c", "n"} <= set(d.keys())):
        # 兜底：若 hint 是 pow(..., ..., n) 形式，从源码外的注释/print 块抽
        # 10733 task.py 是 print("hint=", hint) 而非 hint= <int>——这种情况下
        # 通过 driver 期望 user 显式传参数；这里 skip
        return None
    try:
        from skills.crypto_high_exponent import crypto_high_exponent
        res = crypto_high_exponent({
            "kind": "auto", "c": d["c"], "e": 65536, "n": d["n"], "hint": d["hint"],
            "prefixes": ["DASCTF{", "flag{", "ctf{", "QNFPGS{"],
            "max_flag_len": 128,
        })
    except Exception as exc:  # noqa: BLE001
        logger.debug("[crypto_high_exponent] skill 异常: %s", exc)
        return None
    if not res.get("ok"):
        return None
    # ROT 编码时优先 rot18（题名 "How many rot" → 13+5 = 18），其次 rot13
    for key in ("rot18", "rot13", "flag"):
        f = res.get(key)
        if isinstance(f, str) and re.search(r"(?i)(?:flag|dasctf|ctf)\{[^}\s]+\}", f):
            return f
    return None


@MathEngineMatrix.register("misc_bigfile_lime")
def _engine_misc_bigfile_lime(question):
    """大文件/嵌套压缩包/内存镜像秒级分析（10734 验证）。

    触发：附件 >= 50MB 或 .lime/.raw/.pcapng 后缀。
    主要价值是给 LLM 提供结构信息（zip_list + nested_tail < 5s），
    flag_scan / xor_title_search 在压缩流上跑一次（命中即出）。
    """
    import re

    atts = list(getattr(question, "attachments", None) or [])
    if not atts:
        return None
    # 大附件 / 已知大文件后缀
    _BIG_EXTS = (".zip", ".7z", ".rar", ".tar", ".gz", ".lime", ".raw",
                 ".pcapng", ".pcap", ".img", ".dd", ".mem", ".bin")
    big = [a for a in atts
           if str(a).lower().endswith(_BIG_EXTS)
           or (__import__("os").path.exists(str(a))
               and __import__("os").path.getsize(str(a)) > 50 * 1024 * 1024)]
    if not big:
        return None
    try:
        from skills.misc_bigfile_analysis import misc_bigfile_analysis
    except Exception:
        return None
    for path in big[:1]:  # 只跑第一个大附件，预算 5s
        try:
            res = misc_bigfile_analysis({"kind": "zip_list", "path": str(path)})
        except Exception as exc:  # noqa: BLE001
            logger.debug("[misc_bigfile_lime] zip_list 异常: %s", exc)
            continue
        if not res.get("ok"):
            continue
        # 压缩流上跑 xor_title_search（题名暗示 XOR 时机率高）
        title = str(getattr(question, "title", "") or "")
        if "^" in title or "rot" in title.lower():
            # 提 key：题名首两 token 异或
            try:
                m = re.search(r"\b([A-Za-z]+)\s*\^\s*([A-Za-z]+)\b", title)
                if m:
                    a, b = m.group(1)[:4].encode(), m.group(2)[:4].encode()
                    key = bytes(x ^ y for x, y in zip(a, b))
                    xs = misc_bigfile_analysis({
                        "kind": "xor_title_search", "path": str(path),
                        "key": key, "max_matches": 5,
                    })
                    if xs.get("matches"):
                        for mm in xs["matches"]:
                            if re.search(r"(?i)(?:flag|dasctf|ctf)\{", mm.get("text", "")):
                                m2 = re.search(r"(?i)(?:flag|dasctf|ctf)\{[^}\s]{3,}\}", mm["text"])
                                if m2:
                                    return m2.group(0)
            except Exception:
                pass
        # 压缩流 flag_scan（命中率低，权当兜底）
        try:
            fs = misc_bigfile_analysis({
                "kind": "flag_scan", "path": str(path),
                "patterns": [r"DASCTF\{[^}]{3,}\}", r"flag\{[^}]{3,}\}"],
                "max_matches": 5,
            })
            if fs.get("matches"):
                m = re.search(r"(?i)(?:flag|dasctf|ctf)\{[^}\s]{3,}\}", fs["matches"][0].get("text", ""))
                if m:
                    return m.group(0)
        except Exception:
            pass
    return None


# ── 决赛 S3 接入（2026-08-21）：web CMS 源码包静态审计 ──────────────
# 真题 web 23/32 的"本地有附件、远端靶机关"场景：附件是 joomla/wordpress/
# drupal/ghost/cmsms 完整源码包，flag/后门/配置泄露可静态扫出，无须等靶机。
# 端点探测（endpoints 注入）由 run.py:710 的 P0 修复已做，本处只补源码审计这条腿。

@MathEngineMatrix.register("web_source_audit_cms")
def _engine_web_source_audit_cms(question):
    """web CMS 源码包静态审计（找 flag/后门/配置泄露）。"""
    if getattr(question, "category", "") != "web":
        return None
    atts = list(getattr(question, "attachments", None) or [])
    if not atts:
        return None
    # CMS 指纹：附件文件名/路径含关键字（大小写不敏感）
    _CMS_KEYS = ("joomla", "wordpress", "drupal", "ghost", "cmsms", "cms-made-simple",
                 "cms_", "wp-", "joomla-", "magento", "typo3", "discuz", "phpcms",
                 "帝国", "织梦", "dedecms")
    cms_atts = []
    for a in atts:
        if not isinstance(a, str):
            continue
        low = a.lower().replace("\\", "/")
        if any(k in low for k in _CMS_KEYS):
            if __import__("os").path.exists(a):
                cms_atts.append(a)
    if not cms_atts:
        return None
    try:
        from skills.web_source_audit import run as audit_run
    except Exception:
        return None
    import re as _re
    for path in cms_atts[:1]:  # 只跑第一个，预算 30s（CMS 包通常 5-30MB）
        try:
            res = audit_run({"path": path, "name": path.split("/")[-1].split("\\")[-1]})
        except Exception as exc:  # noqa: BLE001
            logger.debug("[web_source_audit_cms] 异常: %s", exc)
            continue
        for f in res.get("found_flags", []) or []:
            m = _re.search(r"(?i)(?:flag|dasctf|ctf)\{[^}\s]{3,}\}", f.get("match", ""))
            if m:
                return m.group(0)
    return None


def _extract_flag_from_bytes(blob: bytes) -> str | None:
    import re

    if not blob:
        return None
    m = re.search(rb"(?i)(?:flag|dasctf|ctf)\{[^}\s]{3,}\}", blob)
    return m.group(0).decode("utf-8", errors="replace") if m else None


def _extract_flag_from_pdf_text(pdf_path: str) -> str | None:
    try:
        import fitz  # pymupdf
    except ImportError:
        return None
    try:
        doc = fitz.open(pdf_path)
        for pg in doc:
            t = pg.get_text() or ""
            f = _extract_flag_from_bytes(t.encode("utf-8", errors="ignore"))
            if f:
                return f
    except Exception:
        return None
    return None


# ── 便捷入口 ──────────────────────────────────────────


def solve_question(question, timeout: float = 60.0) -> tuple:
    """外部入口：给定 Question，返回 (engine_name, flag)。"""
    return MathEngineMatrix.solve(question, timeout=timeout)
