"""提示词组装模块（上帝模块拆分——main_agent 提示词职责独立）。

从 main_agent 提取：build_plan_prompt / build_reason_prompt /
build_self_reflection / infer_skill_require。
模块级函数接收 ctx（AgentContext 鸭子类型，不 import main_agent 防循环依赖），
逻辑与 main_agent 原实现一致（提取不重构）。

背景（2026-08-20 锐评整改）：main_agent 943 行上帝模块按职责拆——
提示词组装归本模块，兜底脚本归 fallbacks.py，主循环/LLM/校验留 main_agent。
"""

from typing import Optional

from verify.error_classifier import ERR_TOOL_FAILURE  # noqa: F401 - 反思归因用


# ── 解题作战铁律（2026-08-22 并行会话烧 token 事故整改，运行时强制，详见 AGENTS.md 第七節）──
# 每次解题动手前必过一遍；目标：禁手搓替代成熟工具、设止损线、锚定 flag accepted。
SOLVE_DISCIPLINE = """\
【解题作战铁律·每次动手前自检】
1. 工具优先（R1）：动手前先查 skills/ 目录与 web_search 公开 writeup。仓库已有 zip_chain_decode /
   zip_filename_chain_decode（已实测解 10663）/ misc_zip_fake_encryption / rsa_fermat_factor 等现成
   skill，绝不手搓 Z3 / 自研爆破替代。zip 已知明文攻击用 bkcrack（外部工具）。
2. 假设先于实现（R2）：核心假设先做最小成本验证（1 次工具调用能验证的，绝不手写 100 行）。
3. 止损线（R3）：单条技术路线 3 轮不命中即停换方案；每轮先声明"验证什么假设、预算几轮"。
4. 信息优先于暴力（R4）：爆破前先盘点题目自带已知信息（文件头/CRC/时间戳/文件名/注释/同密码规律）
   缩小空间；暴力须向量化且有界（预先声明预算轮数）。
5. 目标锚定（R5）：每步问"这一步在朝 flag accepted 前进，还是在造轮子？"工程完备性不产生分数。
6. 成本核算（R6）：超预算立即汇报，不闷头继续。token = 比赛时钟。
7. 置信度输出（R7，P1-1 盲区分析管道）：每步分析末尾单独一行输出 `confidence: <0-100>`，
   先报信心再动手。该值仅作自评记录（赛后按 solved_by 拆分盲区），不参与任何自动化判定。"""


def build_plan_prompt(ctx, attempt: int) -> str:
    """首轮/每轮 plan 提示词（题型/附件/监督建议/错误归因/已执行步骤）。"""
    q = ctx.question
    parts = [f"题目: {getattr(q, 'title', '')}",
             f"题型: {getattr(q, 'category', '')}",
             str(getattr(q, 'description', '') or '')]
    if getattr(q, 'attachments', None):
        parts.append(f"附件: {', '.join(q.attachments)}")
    if ctx.hint_text:
        parts.append(f"提示: {ctx.hint_text}")
    # 抄 NUS Advisor：监督定向建议注入（AI 卡壳/走偏时修正路径）
    if ctx.advisor_hint:
        parts.append(f"⚠️ 监督建议: {ctx.advisor_hint}")
    parts.append(f"flag 格式: {getattr(q, 'flag_pattern', r'flag\\{[^}]+\\}')}")
    # 结构化修正指令（v2.0 错误归因：明确告诉模型错在哪、关键信息、往哪改）
    if ctx.correction:
        corr = ctx.correction
        cparts = ["⚠️ 上一轮失败，错误归因:"]
        if corr.get("error_category"):
            cparts.append(f"错误类型: {corr['error_category']}")
        if corr.get("key_info"):
            cparts.append(f"关键信息: {corr['key_info']}")
        if corr.get("suggestion"):
            cparts.append(f"修正方向: {corr['suggestion']}")
        parts.append("\n".join(cparts))
    if ctx.steps:
        recent = [f"{s.stage} | {s.action} | {s.observation[:1200]}" for s in ctx.steps[-3:]]
        parts.append("已执行步骤:\n" + "\n".join(recent))
    # presolve web 源码审计报告注入 LLM：presolve 写入 question.extra 的审计线索
    # 必须被 plan/reason prompt 消费，否则 LLM 在 web 题上从零空转。
    _extra = getattr(q, "extra", None) or {}
    _audit = _extra.get("web_audit_report")
    if _audit:
        parts.append(f"【web 源码审计报告】{_audit}")
    parts.append(SOLVE_DISCIPLINE)  # 作战铁律运行时强制注入
    return "\n".join(parts)


def build_reason_prompt(ctx, detail: str) -> str:
    """推理提示（plan 提示 + 本步任务）。"""
    parts = [build_plan_prompt(ctx, 0)]
    if detail:
        parts.append(f"本步任务: {detail}")
    return "\n".join(parts)


def build_self_reflection(ctx, flag: Optional[str], error: Optional[Exception]) -> dict:
    """自动生成结构化反思（基于步骤历史 + 错误归因）。"""
    steps = ctx.steps
    last = steps[-1] if steps else None
    gaps = []
    suggestions = []
    cat = getattr(ctx.question, "category", "")
    if not flag:
        if ctx.stuck_count >= 3:
            gaps.append(f"{cat}题型连续 {ctx.stuck_count} 次失败，缺少有效攻击路径")
        if steps and all(s.action == "reason" for s in steps[-3:]):
            gaps.append("纯推理空转，缺少工具调用/脚本执行获取真实证据")
        if steps and any(s.error_category == ERR_TOOL_FAILURE for s in steps[-3:]):
            gaps.append(f"{cat}题型工具执行失败，缺少可用工具或参数配置")
        if not getattr(ctx.question, "attachments", None) and cat in ("crypto", "misc", "reverse", "pwn"):
            gaps.append(f"{cat}题型缺少附件数据，可能需要靶机交互")
        # 推理跳步检测
        if steps and len(steps) <= 2 and not ctx._attachment_analyzed and getattr(ctx.question, "attachments", None):
            gaps.append("推理跳步：附件未解析就尝试解题")
            suggestions.append("优先解析附件，提取全部参数/线索后再推理")
        suggestions.append("换工具/换思路/换目标文件，至少尝试 3 种不同方向")
        if cat == "pwn":
            suggestions.append("pwn 题需 pwntools + GDB 本地调试堆布局，远程盲打成功率低")
        elif cat == "web":
            suggestions.append("web 题优先查看源码/备份文件/目录扫描，再构造 payload")
    else:
        suggestions.append("解出成功，检查是否有更优路径")
    what_i_did = "; ".join(
        f"{s.stage}:{s.action}" for s in steps[-3:]
    ) if steps else "无步骤记录"
    success_reason = "成功解出 flag" if flag else (
        str(error)[:200] if error else (
            f"未解出：stuck_count={ctx.stuck_count}, steps={len(steps)}, "
            f"last_error={last.error_category if last else 'none'}"
        )
    )
    return {
        "what_i_did": what_i_did,
        "success_or_failure_reason": success_reason,
        "ability_gap": gaps if gaps else ["无明显能力缺口"],
        "strategy_adjust_suggestion": suggestions,
    }


def infer_skill_require(ctx, reflection: dict, skill_manager=None) -> Optional[dict]:
    """从 ability_gap 推断是否需要请求新 Skill（仅允许加载本地已验证 skill）。

    2026-08-22 锐评整改（路由表瘦身+锁死）：
    - 去重：删除重复键（Python dict 字面量重复键静默覆盖，前面的映射是死代码）
    - 修错键：vigenere_crack→vigenere_decode（真实文件名）；misc_stego_general 等
      不存在的 skill 映射一律删除
    - 锁死下载：need_download 不再可能指向不存在的 skill——映射表只允许
      引用 skills/ 目录真实存在的 skill；本地有→加载，本地无→返回 None
      （不请求下载未验证 skill，防临场加载装饰性火力消耗墙钟）
    """
    gaps = reflection.get("ability_gap", [])
    if not gaps or gaps == ["无明显能力缺口"]:
        return None
    desc = str(getattr(ctx.question, "description", "") or "").lower()
    # 键唯一（2026-08-22 去重）；值全部为 skills/ 目录真实存在的 skill 名
    skill_map = {
        # ── 基础题型（测试赛/赛后 12 真题实证过的 skill）──
        "morse": "morse_decoder", "摩斯": "morse_decoder",
        "费马": "rsa_fermat_factor", "fermat": "rsa_fermat_factor", "rsa": "rsa_fermat_factor",
        "zip": "zip_chain_decode", "压缩": "zip_chain_decode",
        "base64": "base64_multilayer", "base32": "base64_multilayer",
        "凯撒": "caesar_bruteforce", "caesar": "caesar_bruteforce",
        "移位": "caesar_bruteforce", "位移": "caesar_bruteforce",
        "md5": "hash_crack", "sha1": "hash_crack", "sha256": "hash_crack",
        "哈希": "hash_crack", "hash": "hash_crack",
        "维吉尼亚": "vigenere_decode", "vigenere": "vigenere_decode",
        "kasiski": "vigenere_decode", "频率分析": "vigenere_decode",
        # ── 测试赛/正式赛沉淀的新 skill 关键词映射（均已存在于 skills/）──
        "反序列化": "java_deserialization_flow", "deserialize": "java_deserialization_flow",
        "unserialize": "php_unserialize_pop", "pop": "php_unserialize_pop",
        "nashorn": "java_nashorn_response", "无回显": "java_nashorn_response",
        "上传": "web_upload_bypass", "upload": "web_upload_bypass", "xxe": "web_xxe_file_read",
        "uaf": "pwn_exploit_flow", "堆溢出": "pwn_exploit_flow",
        "seccomp": "pwn_sandbox_escape", "沙盒": "pwn_sandbox_escape",
        "格攻击": "crypto_lattice_attack", "lll": "crypto_lattice_attack",
        "流量": "misc_traffic_analysis", "pcap": "misc_traffic_analysis",
        "混淆": "reverse_obfuscation", "ollvm": "reverse_obfuscation",
        "审计": "web_source_audit", "源码": "web_source_audit",
        # ── 决赛预研/备用路线 skill 关键词映射（均已存在于 skills/）──
        "coppersmith": "crypto_coppersmith", "部分私钥": "crypto_coppersmith", "partial": "crypto_coppersmith",
        "ret2dlresolve": "pwn_ret2dlresolve", "无 libc": "pwn_ret2dlresolve", "无libc": "pwn_ret2dlresolve",
        "盲打": "pwn_nogdb_flow", "无 gdb": "pwn_nogdb_flow", "无gdb": "pwn_nogdb_flow",
        "多步链": "web_multi_step_chain", "组合利用": "web_multi_step_chain",
        "条件竞争": "web_race_condition", "race": "web_race_condition",
        "二次注入": "web_second_order_injection", "second order": "web_second_order_injection",
        "ssti": "ssti_detect", "模板注入": "ssti_detect",
        "sqli": "web_sqli", "sql注入": "web_sqli",
        "ssrf": "web_ssrf", "内网探测": "web_ssrf",
        "zip_filename": "zip_filename_chain_decode",
        "n接近": "rsa_fermat_factor", "p和q接近": "rsa_fermat_factor", "大素数差小": "rsa_fermat_factor",
        "磁盘": "misc_disk_forensics", "raid": "misc_disk_forensics",
        "分区": "misc_disk_forensics", "img镜像": "misc_disk_forensics",
        "ECB": "crypto_ecb_block_attack", "分组密码": "crypto_ecb_block_attack",
        "字节攻击": "crypto_ecb_block_attack", "块加密": "crypto_ecb_block_attack",
        "oracle": "crypto_ecb_block_attack",
        "抓包": "misc_traffic_analysis", "wireshark": "misc_traffic_analysis",
        "tshark": "misc_traffic_analysis", "dns查询": "misc_traffic_analysis",
        "ELF": "reverse_elf_general", "可执行文件": "reverse_elf_general",
        "strings": "reverse_elf_general", "符号表": "reverse_elf_general",
        "pyc": "pyc_decompile", "python字节码": "pyc_decompile",
        "safe-linking": "pwn_tcache_safelinking", "tcache": "pwn_tcache_safelinking",
        "堆利用": "pwn_tcache_safelinking", "glibc2.31": "pwn_tcache_safelinking",
        "JWT": "web_jwt_prototype", "token伪造": "web_jwt_prototype",
        "原型链": "web_jwt_prototype", "__proto__": "web_jwt_prototype",
        "伪加密": "zip_filename_chain_decode", "zip密码": "zip_filename_chain_decode",
        "明文攻击": "crypto_coppersmith", "小根方程": "crypto_coppersmith",
        "部分密钥": "crypto_coppersmith",
        "返回导向": "pwn_ret2dlresolve", "无libc利用": "pwn_ret2dlresolve",
        "沙盒绕过": "pwn_sandbox_escape",
        "并发请求": "web_race_condition",
        "二次编码": "web_second_order_injection",
        "源码审计": "web_source_audit", "危险函数": "web_source_audit",
        "文件读取": "web_xxe_file_read",
        "上传绕过": "web_upload_bypass", "webshell": "web_upload_bypass",
        "布尔盲注": "web_sqli",
        "爆破": "hash_crack", "弱密码": "hash_crack", "字典": "hash_crack", "彩虹表": "hash_crack",
        "rot13": "base64_multilayer", "rot": "base64_multilayer",
        "编码": "base64_multilayer", "解码": "base64_multilayer",
        "多层编码": "base64_multilayer", "url编码": "base64_multilayer",
        "hex": "base64_multilayer", "urldecode": "base64_multilayer",
        # 注（2026-08-23 裁决③）：rsa_fermat_factor 的 docstring 是「RSA 攻击全套」，
        # 内部 auto-detect 费马/小指数/Wiener/共模/Hastad/phi已知——文件名"费马"是历史
        # 遗留误导。以下所有 RSA 关键词路由到它，靠内部自动检测兜底，非仅费马分解。
        "小指数": "rsa_fermat_factor", "小e": "rsa_fermat_factor",
        "广播攻击": "rsa_fermat_factor", "hastad": "rsa_fermat_factor",
        "crt": "rsa_fermat_factor", "中国剩余": "rsa_fermat_factor",
        "共模": "rsa_fermat_factor", "common modulus": "rsa_fermat_factor",
        "wiener": "rsa_fermat_factor", "连分数": "rsa_fermat_factor",
        "小d": "rsa_fermat_factor", "私钥小": "rsa_fermat_factor",
        "逆元": "rsa_fermat_factor", "inverse": "rsa_fermat_factor",
        "phi": "rsa_fermat_factor", "欧拉函数": "rsa_fermat_factor",
        "栅栏": "base64_multilayer", "培根": "base64_multilayer",
        # ── 补回有效键（2026-08-22 复核：指向真实存在 skill，不可误删）──
        "坏道": "misc_disk_forensics", "取证": "misc_disk_forensics",
        "内存": "misc_disk_forensics", "Volatility": "misc_disk_forensics",
        "usb键盘": "misc_traffic_analysis",
        "反编译": "pyc_decompile",
        "js合并": "web_jwt_prototype",
        "压缩包损坏": "zip_filename_chain_decode",
        "维吉尼亚密码": "vigenere_decode",
    }
    for keyword, skill_name in skill_map.items():
        if keyword in desc or keyword in " ".join(gaps).lower():
            # 检查本地是否已加载
            if skill_manager and skill_name in skill_manager.list_loaded():
                return None  # 已加载，无需下载
            if skill_manager and skill_name in skill_manager.list_available():
                # 本地有但未加载 → 自动加载
                skill_manager.load(skill_name)
                return None
            # 锁死（2026-08-22）：映射表已只允许引用真实 skill；若仍本地缺失
            # （skill 目录被裁剪/改名），不请求下载未验证 skill——直接放弃。
            return None
    return None
