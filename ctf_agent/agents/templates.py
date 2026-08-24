"""辅助：典型场景快速 payload 生成（非核心得分项）。

v2.0 定位：模板缓存降级为辅助工具——主 Agent 在判断题型后，
从各工具包取 payload 模板作为参考输入，加速典型场景的初探，
不作为评分依据（评委考察 AI 自主解题能力，非背题秒解）。
"""

from __future__ import annotations

from typing import Optional

from agents.web_toolkit import WebToolkit
from agents.crypto_toolkit import CryptoToolkit
from agents.misc_toolkit import MiscToolkit


class TemplateBank:
    """统一模板库：按题型取 payload/攻击模板。"""

    def __init__(self) -> None:
        self._web = WebToolkit()
        self._crypto = CryptoToolkit()
        self._misc = MiscToolkit()

    def payloads(self, category: str, scene: Optional[str] = None) -> list:
        """按题型取 payload/攻击模板列表。

        Args:
            category: web / crypto / misc
            scene: 可选子场景（如 sqli/rsa/lsb），None 时返回全部
        """
        if category == "web":
            templates = self._web.payload_templates
            if scene:
                return templates.get(scene, [])
            return [item for items in templates.values() for item in items]
        if category == "crypto":
            templates = self._crypto.attack_templates
            if scene:
                return [templates.get(scene, "")]
            return list(templates.values())
        if category == "misc":
            templates = self._misc.attack_templates
            if scene:
                return [templates.get(scene, "")]
            return list(templates.values())
        return []

    def suggest_steps(self, category: str, description: str, attachments: Optional[list] = None) -> list[str]:
        """按题型与题目描述给出初始步骤建议。"""
        if category == "web":
            return self._web.suggest_steps(description, attachments)
        if category == "crypto":
            return self._crypto.suggest_steps(description, attachments)
        if category == "misc":
            return self._misc.suggest_steps(description, attachments)
        return ["通用分析：file/strings/题目描述关键词定位"]

    # ── 题型标准解题流程（抄 CTF-Kit / Amadeus：定义每题型工具调用顺序）──
    # 让主 Agent 在 plan 时按标准流程走，减少试错（对应文档 3.2.5 题型适配参考）

    STANDARD_FLOWS: dict = {
        "web": [
            "1. 【先扫明文 flag】直接调用 flag_scan 工具（attachments 传附件路径），"
            "递归扫全部文本文件——flag 常写在源码注释/HTML alert/JS/备份文件里（源码审计类秒出）；"
            "再信息收集: 用 http_request 探测目标 URL 的路径/参数/响应头/源码（?source/备份 .bak/.zip）",
            "2. 漏洞识别: 按描述关键词定向探测（SQLi 万能密码 / SSTI {{7*7}} / 命令注入 ;id / JWT 弱密钥 / 上传 / XXE / 反序列化）",
            "3. 构造 payload: 用精准定向 payload（不暴力字典），适配过滤绕过",
            "4. 提取响应中的 flag 提交",
            "5. 【上传类题】先探测 XXE（SVG 上传读 /flag），再试图片马/双扩展名",
            "6. 【Java 反序列化】javap 反编译找入口（参数名看 MethodParameters 表，注意大小写），"
            "classpath 找 gadget（commons-collections 等），无回显时用 Nashorn/ScriptEngine 反射改响应",
        ],
        "crypto": [
            "1. 读附件提取参数（n/e/c/p/q/phi/密文/哈希/编码串）：file_analyze 仅给 strings 摘要，"
            "文本附件（.py/.out/.txt/.json/output）必须改用 script 直接读原始内容 "
            "（code: python: p=open(r'PATH').read(); print(p[:2000])），否则拿不到结构化的 e/phi/c 映射",
            "2. 识别算法类型（RSA 小指数/共模/Wiener/Fermat p-q 相近/已知 phi 直接求 d、凯撒/维吉尼亚、base64/hex、哈希、AES-ECB、格攻击）",
            "2b. 【确定性 skill 触发】A/B 字符序列→调 morse_ab_decode skill（摩斯解码+UUID定位）；"
            "key:/data: 格式或八进制/多层编码→调 vigenere_decode skill（自动提取+解密）；"
            "JPEG 尾部异常/多文件头→调 jpeg_png_embedded skill（嵌入图片提取）",
            "3. 【一键直出·最高优先】直接调用 crypto_auto 工具（参数 attachments 传附件绝对路径列表），"
            "它会自动嗅探 RSA 参数（已知phi/逆元、Hastad 广播 e 爆破、共模、费马、Wiener、small_e）并执行确定性攻击，"
            "同时尝试哈希爆破与多层编码，命中即返回 flag（实测 ExcitingInverse/ezRSA 秒解，无需自己写攻击脚本）；"
            "crypto_auto 未命中再走下面的模板脚本。",
            "4. 编码题(b64/hex/rot13/utf-7)直出脚本(沙盒可直接执行,无需import): "
            "code: python: import base64,codecs; t=open(r'PATH').read().strip(); "
            "import sys; "
            "for f in [lambda x:base64.b64decode(x+'='*(-len(x)%4)).decode('utf-8','ignore'),"
            "lambda x:codecs.encode(x,'rot13'),"
            "lambda x:base64.b64decode(x.replace('-','+')).decode('utf-16-be','ignore')]: "
            "try: print(f(t)); except: pass",
            "5. RSA 已知 phi: d=pow(e,-1,phi); m=pow(c,d,n); from Crypto.Util.number import long_to_bytes; print(long_to_bytes(m))",
            "6. 用 python 脚本计算/爆破（模板库 attack_templates 提供算法）",
            "7. 【AES-ECB 黑盒 oracle】构造输入对齐块边界（byte-at-a-time：filler 使目标字节落块尾，"
            "字典比对恢复未知明文）——crypto_ecb_block_attack skill",
            "8. 【格攻击】参数含部分位/多方程小未知数/HNP → crypto_lattice_attack（纯 Python LLL）",
            "9. 将明文结果转 flag 格式校验提交",
        ],
        "misc": [
            "1. 用 file_analyze 读附件（文件类型/strings/尾部数据）",
            "2. 按特征定位（LSB 隐写/伪加密 zip/尾部附加/编码/摩斯/DNS 隧道/多层嵌套 zip）",
            "3. 用模板脚本提取（lsb_extract/fix_fake_encryption/check_tail/解码）",
            "4. 多层 zip: 循环解压至底层，注意文件名链编码（base32/64/58/62/36/摩斯/培根 自动探测）与陷阱 flag",
            "5. 提取 flag 提交",
        ],
        "reverse": [
            "1. 【先扫明文 flag】直接调用 flag_scan 工具（attachments 传附件路径）扫全部附件文件，"
            "flag 可能在非主文件（如 index.html 注释/coso.js 编码/README/备份文件），扫到直接提交；"
            "再列附件目录所有文件（ls/FindFirstFile），二进制文件先 file/checksec + strings 扫硬编码 flag"
            "（PE/MFC 题 strings 直出是高频路径）",
            "2. 加壳检测（UPX/ASPack）→ 先脱壳（upx -d / unpacker 脚本）再分析",
            "3. 分析校验逻辑（字符串比较/字节码反编译 py uncompyle6/decompyle4/算法还原）",
            "4. 提取或还原 flag 后必须 long_to_bytes/decode 确认可读，禁止提交含乱码的 flag",
            "5. 提取 flag 提交",
        ],
        "pwn": [
            "1. 附件先 file/checksec（PIE/RELRO/Canary/NX 保护状态）",
            "2. 用 capstone 反汇编菜单功能，定位漏洞原语（free 后未清指针 UAF/栈溢出/格式化字符串/越界写）",
            "3. 设计利用链：非 PIE+system → 直接覆盖函数指针；PIE → 先泄露基址；全保护堆 → tcache/fastbin 攻击",
            "4. 用 pwntools 交互验证（注意 read 是裸字节流用 send，fgets 是行读用 sendline）",
            "5. 构造 payload 打远程拿 flag",
        ],
    }

    def standard_flow(self, category: str) -> list[str]:
        """按题型返回标准解题流程（工具调用顺序建议）。"""
        return self.STANDARD_FLOWS.get(category, [])

    # ── Skill 技能库（抄 CyberStrikeAI：按题型+场景封装可复用技能）──
    # 场景清单：与各 toolkit 的 payload_templates/attack_templates key 对齐

    SKILL_SCENES: dict = {
        "web": ["sqli_login_bypass", "sqli_extract", "xss_probe", "ssti_probe",
                "ssti_rce_jinja", "upload_probe", "path_traversal",
                "unserialize_probe", "ssrf_probe"],
        "crypto": ["caesar", "vigenere", "rsa_small_e", "rsa_common_modulus",
                   "rsa_wiener", "hash_crack", "base64_multi"],
        "misc": ["lsb_extract", "zip_fake_encryption", "brainfuck_run",
                 "tail_append_check"],
    }

    def skill(self, category: str, scene: str) -> Optional[dict]:
        """按题型+场景取技能卡片（payload/攻击模板 + 标准流程）。

        对应 CyberStrikeAI「AI 模型根据题目类型调用对应 Skill，
        直接初始化标准解题路径」——主 Agent/兜底可据此精准初始化。

        Returns:
            {"category", "scene", "payloads": [...], "flow": [...]}；无匹配返回 None
        """
        payloads = self.payloads(category, scene)
        if not payloads:
            return None
        return {
            "category": category,
            "scene": scene,
            "payloads": payloads,
            "flow": self.standard_flow(category),
        }

    def available_scenes(self, category: str) -> list[str]:
        """某题型可用的 Skill 场景清单（技能库目录）。"""
        return self.SKILL_SCENES.get(category, [])
