# -*- coding: utf-8 -*-
"""web_source_audit：CMS/Web 服务器源码审计确定性流程（决赛 web 题弹药）。

背景（2026-08-21 分类回归）：正式赛 32 题中 23 题是 web 源码审计类
（joomla/wordpress/drupal/cmsms/ghost + nginx/httpd/caddy/openresty/postgresql/redis
等官方源码包）。这类题 flag 不在明文里，需要：① 定位被植入的修改/后门；
② 找敏感文件/配置；③ 结合版本号映射已知 CVE → 靶机交互攻破。

本 skill 提供前三步的确定性流程，输出结构化审计报告，供 LLM / presolve /
操作员快速定位攻击面。

用法：
    from skills.web_source_audit import run
    result = run({"path": "/path/to/attachment_or_dir", "name": "REAL-01"})
"""
import base64
import json
import os
import re
import tarfile
import time
import zipfile

# ── flag 特征（含赛题验证过的变体：rot13 的 DASCTF{ = QNFPGS{）──
FLAG_PATTERNS = [
    (r"(?i)\b(flag|d3ctf|xctf|hgame|ctf)\{[A-Za-z0-9_\-!@#$%^&*+=:.?]{4,}\}", "明文flag"),
    (r"QNFPGS\{[A-Za-z0-9_\-]{4,}\}", "rot13(DASCTF{...)=QNFPGS{..."),
]
# 常见隐蔽形式：被拆分的 flag 片段（要求 12+ 字符，排除 JS/模板常见对象键）
SPLIT_PATTERN = re.compile(r"(?i)\bflag\s*[=:]\s*['\"]([A-Za-z0-9_\-]{12,})['\"]")
_SPLIT_STOP = ("showtitle", "showmedia", "showdescription", "showauthor", "showdate",
               "showhits", "showcategory", "showrating", "showtags", "showmeta",
               "sortorder", "sortby", "orderby", "pagination", "paginator",
               "totalpages", "currentpage", "currentuser", "adminemail",
               "siteurl", "sitename", "homeurl", "blogname", "description",
               "memberdetailsreact", "tagdetailsreact", "supereditors",
               "editorexcerpt", "additionalpaymentmethods", "memberdetails",
               "tagdetails", "showtitle", "featuredimage", "featuredpost")

# ── 后门/危险函数特征（PHP 优先，覆盖 PY/JSP/ASP/JS）──
BACKDOOR_PATTERNS = [
    (r"eval\s*\(\s*base64_decode\s*\(", "eval+base64_decode 加密后门"),
    (r"(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(\s*\$_?(?:GET|POST|REQUEST|COOKIE)", "命令执行参数注入"),
    (r"assert\s*\(\s*\$_?(?:GET|POST|REQUEST)", "assert 参数后门"),
    (r"eval\s*\(\s*\$_(?:GET|POST|REQUEST)", "eval 参数后门"),
    (r"create_function\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\$_?(?:GET|POST|REQUEST)", "create_function 后门"),
    (r"gzinflate\s*\(\s*base64_decode", "gzip 压缩后门"),
    (r"str_rot13\s*\(\s*['\"][A-Za-z0-9+/=]{20,}", "rot13 混淆后门"),
    (r"file_put_contents\s*\(\s*\$_?(?:GET|POST|REQUEST)", "写文件后门"),
    (r"move_uploaded_file\s*\([^)]*\$_(?:GET|POST|REQUEST)", "上传后门"),
    (r"\$_(?:GET|POST|REQUEST)\[[^]]*\]\s*\(\s*\$_(?:GET|POST|REQUEST)", "动态调用后门"),
]

# ── 敏感文件/目录（排除第三方库噪声）──
SENSITIVE_NAMES = [
    ".env", "config.php", "wp-config.php", "configuration.php", "settings.php",
    "database.php", "db.sql", "dump.sql", "backup", "*.bak", "*.old", "*.swp",
    "*.orig", ".git", ".svn", ".htaccess", "htaccess.txt", "readme", "readme.txt",
    "readme.md", "secret", "secret.txt", "hint", "flag", "shell", "webshell",
    "upload", "uploads", "temp", "tmp", "phpinfo",
]
NOISE_DIRS = ("vendor", "node_modules", "media", "libraries/vendor", "cache", "logs")

# 版本号提取：joomla-6.1.2 / nginx_1.31.4 / caddy-2.11.4 ...
VERSION_RE = re.compile(r"(joomla|wordpress|drupal|cmsms|ghost|nginx|httpd|apache|"
                        r"openlitespeed|caddy|openresty|postgresql|redis|mariadb|"
                        r"mongodb|clickhouse|mysql|php)[\-_ ]?v?(\d[\w.]*)", re.I)


class _Budget:
    """扫描预算：时间 + 文件数双上限（锐评 A1——无预算全量扫导致 180s 挂起）。

    大 CMS 包（joomla 6.x 展开后 3000+ 文件）全量正则扫会拖垮 presolve/测试门禁；
    触顶即截断并在报告标注 truncated，宁可漏扫尾部也不阻塞解题链路。
    """

    def __init__(self, time_limit: float = 25.0, max_files: int = 4000):
        self.time_limit = time_limit
        self.max_files = max_files
        self.t0 = time.monotonic()
        self.files = 0
        self.truncated = False

    def bump(self) -> bool:
        """计一个文件；超预算返回 True（调用方应停止遍历）。"""
        self.files += 1
        if self.files > self.max_files or time.monotonic() - self.t0 > self.time_limit:
            self.truncated = True
        return self.truncated


def _norm_flag(text: str):
    """对文本做常见编码归一化，便于匹配被混淆的 flag。"""
    out = []
    try:
        out.append(base64.b64decode(text).decode("utf-8", "ignore"))
    except Exception:
        pass
    try:
        out.append(text.encode("utf-8").decode("rot13"))
    except Exception:
        pass
    return [t for t in out if t and len(t) > 4]


def _extract_archives(root: str) -> list:
    """递归解压 zip/tar.gz/tgz，返回解压后目录列表。"""
    extracted = []
    for dirpath, dirnames, filenames in os.walk(root):
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            low = fn.lower()
            try:
                if low.endswith(".zip"):
                    target = os.path.join(dirpath, fn[:-4])
                    with zipfile.ZipFile(fp) as z:
                        z.extractall(target)
                    extracted.append(target)
                elif low.endswith((".tar.gz", ".tgz")):
                    target = os.path.join(dirpath, fn[: fn.rfind(".")])
                    with tarfile.open(fp, "r:gz") as t:
                        t.extractall(target)
                    extracted.append(target)
            except Exception:
                pass
    return extracted


def _scan_flags(root: str, budget: "_Budget | None" = None) -> list:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        # 跳过噪声目录
        dirnames[:] = [d for d in dirnames if d.lower() not in NOISE_DIRS and not d.startswith(".")]
        if budget and budget.truncated:
            break
        for fn in filenames:
            low = fn.lower()
            if low.endswith((".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ttf",
                             ".eot", ".ico", ".pyc", ".zip", ".gz")):
                continue
            if budget and budget.bump():
                break
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 5 * 1024 * 1024:
                    continue
                data = open(fp, "rb").read()
                try:
                    text = data.decode("utf-8", "ignore")
                except Exception:
                    continue
            except Exception:
                continue
            for pat, label in FLAG_PATTERNS:
                for m in re.finditer(pat, text):
                    found.append({"file": fp, "match": m.group(0)[:120], "type": label})
            # 拆分 flag 片段（如 flag = "DASCTF{" + "abc}"）
            for m in SPLIT_PATTERN.finditer(text):
                g = m.group(1)
                # 纯驼峰单词（React/模板属性 flag="ComponentName"）一律丢弃；
                # 真 flag 片段通常含 _ / - / 数字 / 大括号
                if g.lower() not in _SPLIT_STOP and re.search(r"[_\-\d{}]", g):
                    found.append({"file": fp, "match": m.group(0)[:120], "type": "疑似拆分flag片段"})
            # base64 长串（可 decode 出 flag 关键字）
            for m in re.finditer(r"[A-Za-z0-9+/=]{24,}", text):
                if m.group(0).endswith("=") or len(m.group(0)) >= 40:
                    for dec in _norm_flag(m.group(0)):
                        if re.search(r"(?i)flag|d3ctf|xctf|ctf", dec):
                            found.append({"file": fp, "match": f"base64→{dec[:100]}", "type": "base64编码flag"})
            # 裸 hex 摘要型 flag（MD5 32 / SHA256 64），仅当同行含 flag/secret/hash
            # 等关键字时才认，避免把源码普通 hex 误报成 flag。
            for line in text.splitlines():
                if not re.search(r"(?i)\b(flag|secret|hash|md5|sha|key)\b", line):
                    continue
                for hm in re.finditer(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{64}\b", line):
                    h = hm.group(0)
                    if re.search(r"(?i)flag|secret|hash|md5|sha|key", h):
                        continue
                    found.append({"file": fp, "match": h, "type": f"裸hex摘要flag({len(h)}位)"})
    return found


def _scan_backdoors(root: str, budget: "_Budget | None" = None) -> list:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in NOISE_DIRS]
        if budget and budget.truncated:
            break
        for fn in filenames:
            if not fn.endswith((".php", ".py", ".jsp", ".asp", ".aspx", ".js")):
                continue
            if budget and budget.bump():
                break
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 2 * 1024 * 1024:
                    continue
                text = open(fp, "rb").read().decode("utf-8", "ignore")
            except Exception:
                continue
            for pat, label in BACKDOOR_PATTERNS:
                if re.search(pat, text):
                    found.append({"file": fp, "type": label})
    # 去重
    seen = set()
    uniq = []
    for f in found:
        k = (f["file"], f["type"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def _scan_sensitive(root: str, budget: "_Budget | None" = None) -> list:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in NOISE_DIRS]
        if budget and budget.truncated:
            break
        for fn in filenames:
            if budget and budget.bump():
                break
            low = fn.lower()
            hit = False
            for pat in SENSITIVE_NAMES:
                p = pat.lower()
                if p in low or low.endswith(p):
                    hit = True
                    break
            if hit and not low.endswith((".css", ".js.map")):
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                if len(rel.split(os.sep)) <= 4:  # 只报浅层，避免刷屏
                    found.append(rel)
    return found[:60]


def _cve_candidates(name: str, root: str) -> list:
    cands = []
    m = VERSION_RE.search(name or "")
    if m:
        soft, ver = m.group(1), m.group(2)
        cands.append({"software": soft, "version": ver,
                      "hint": f"{soft} {ver} 已知漏洞检索（CVE/NVD/exploit-db）"})
    # 从解压目录名再试一次
    if not cands:
        try:
            for d in os.listdir(root):
                m = VERSION_RE.search(d)
                if m:
                    cands.append({"software": m.group(1), "version": m.group(2),
                                  "hint": f"{m.group(1)} {m.group(2)} 已知漏洞检索"})
                    break
        except Exception:
            pass
    return cands


def run(params: dict):
    """统一入口：审计源码包/目录，返回结构化报告。"""
    path = params.get("path", "")
    name = params.get("name", "")
    if not path or not os.path.exists(path):
        return {"error": f"路径不存在: {path}", "found_flags": [], "backdoors": [],
                "sensitive_files": [], "cve_candidates": [], "report": ""}

    # 1. 解压（若是压缩包）
    extracted = _extract_archives(path)
    root = path
    if extracted and not os.path.isdir(path) or (extracted and os.listdir(path) == []):
        pass
    # 若 path 是单个压缩包 → 解压到同级目录后审计
    if os.path.isfile(path):
        _extract_archives(os.path.dirname(path))
        root = os.path.dirname(path)

    # 2. 审计（带预算：时间+文件数双上限，触顶截断不阻塞）
    budget = _Budget(
        time_limit=float(params.get("time_limit", 25.0)),
        max_files=int(params.get("max_files", 4000)),
    )
    flags = _scan_flags(root, budget)
    backdoors = _scan_backdoors(root, budget)
    sensitive = _scan_sensitive(root, budget)
    cves = _cve_candidates(name, root)

    # 3. 报告
    lines = [f"=== web_source_audit: {name or os.path.basename(root)} ==="]
    if budget.truncated:
        lines.append(f"[budget] 扫描截断：已扫 {budget.files} 文件 / "
                     f"{budget.time_limit:.0f}s 上限——尾部未扫，LLM 可续攻")
    lines.append(f"[flags] 命中 {len(flags)}")
    for f in flags[:10]:
        lines.append(f"  {f['file']} | {f['type']} | {f['match']}")
    lines.append(f"[backdoors] 命中 {len(backdoors)}")
    for b in backdoors[:10]:
        lines.append(f"  {b['file']} | {b['type']}")
    lines.append(f"[sensitive] {len(sensitive)} 个敏感文件（前 15）")
    for s in sensitive[:15]:
        lines.append(f"  {s}")
    lines.append(f"[cve] {len(cves)} 个版本候选")
    for c in cves:
        lines.append(f"  {c['hint']}")

    return {
        "name": name,
        "found_flags": flags,
        "backdoors": backdoors,
        "sensitive_files": sensitive,
        "cve_candidates": cves,
        "report": "\n".join(lines),
    }


if __name__ == "__main__":
    import sys
    p = sys.argv[1] if len(sys.argv) > 1 else "."
    n = sys.argv[2] if len(sys.argv) > 2 else ""
    res = run({"path": p, "name": n})
    print(res.get("report", json.dumps(res, ensure_ascii=False, indent=1)))
