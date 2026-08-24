# -*- coding: utf-8 -*-
"""scene#8 数据分析及可视化 — 数据采集器
汇总 ctf_agent 全部可统计数据源 → 输出单份 stats.json（供看板/报告消费）
运行: .venv/Scripts/python.exe scripts/analysis/_scene8_collect.py
"""
import json, os, re, glob, collections, sys, datetime

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(BASE, "data")
RES = os.path.join(DATA, "results")
LOGS = os.path.join(BASE, "logs")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_scene8_stats.json")

def load_json(p, default=None):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def count_lines(p):
    try:
        with open(p, encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

stats = {}

# ============ 1. 仓库规模 ============
skip = {"data", "logs", ".git", ".venv", "__pycache__", ".git.broken_20260822", ".git.broken_orig", ".pytest_cache", ".git.broken_orig_20260822"}
exts = collections.Counter(); total = 0; total_lines = 0
for dp, dns, fns in os.walk(BASE):
    dns[:] = [d for d in dns if d not in skip and not d.endswith("__pycache__")]
    if ".git" in dp or "node_modules" in dp:
        continue
    for f in fns:
        total += 1
        ext = os.path.splitext(f)[1].lower() or "(无)"
        exts[ext] += 1
        if ext in (".py", ".md", ".json", ".sh", ".html", ".txt", ".java", ".c", ".h", ".php"):
            total_lines += count_lines(os.path.join(dp, f))
stats["repo"] = {
    "total_files": total,
    "exts": dict(exts.most_common()),
    "text_lines": total_lines,
}

# ============ 2. 技能库 ============
skills = []
for jf in sorted(glob.glob(os.path.join(BASE, "skills", "*.json"))):
    j = load_json(jf)
    if j:
        nm = os.path.splitext(os.path.basename(jf))[0]
        skills.append({
            "name": nm,
            "domain": (j.get("domain") or j.get("category") or nm.split("_")[0] if "_" in nm else nm),
            "desc": (j.get("description") or j.get("desc") or "")[:80],
        })
cat_skills = collections.Counter(s.get("domain") for s in skills)
stats["skills"] = {"count": len(skills), "by_domain": dict(cat_skills.most_common()), "items": skills}

# ============ 3. 真题清单 ============
rc = load_json(os.path.join(DATA, "real_challenges.json"), []) or []
stats["challenges"] = {
    "total": len(rc),
    "by_cat": dict(collections.Counter(x.get("category") for x in rc)),
}

# ============ 4. 赛题详情(race_details) ============
summ = load_json(os.path.join(DATA, "race_details", "_summary.json"), {}) or {}
diff_c = collections.Counter(); score_c = collections.Counter(); att_c = 0
names = []
for v in summ.values():
    diff_c[v.get("diff", "?")] += 1
    score_c[str(v.get("score", "0"))] += 1
    if v.get("atts"): att_c += 1
    names.append(v.get("name"))
total_score = sum(float(v.get("score") or 0) for v in summ.values())
stats["race_details"] = {
    "count": len(summ),
    "by_diff": dict(diff_c),
    "by_score": dict(sorted(score_c.items(), key=lambda x: float(x[0]))),
    "with_attachments": att_c,
    "total_score": total_score,
    "names": names,
}

# ============ 5. 分类回归(category_regression) ============
cr = load_json(os.path.join(RES, "category_regression.json"), []) or []
stats["regression"] = {
    "total": len(cr),
    "by_cat": dict(collections.Counter(x.get("category") for x in cr)),
    "by_diff": dict(collections.Counter(x.get("difficulty") for x in cr)),
    "solved": sum(1 for x in cr if x.get("flag")),
    "has_att": sum(1 for x in cr if x.get("has_local_attachments")),
    "by_cat_diff": {},
}
_cd = collections.defaultdict(collections.Counter)
for x in cr:
    _cd[x.get("category")][x.get("difficulty")] += 1
stats["regression"]["by_cat_diff"] = {k: dict(v) for k, v in _cd.items()}

# ============ 6. goal_log ============
gl_rows = []
with open(os.path.join(RES, "goal_log.jsonl"), encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                gl_rows.append(json.loads(line))
            except Exception:
                pass
err_cls = collections.Counter(); err_cat = collections.Counter()
hourly = collections.Counter(); task_c = collections.Counter(); type_c = collections.Counter()
success = 0; retries_sum = 0
for r in gl_rows:
    es = r.get("error_struct") or {}
    c4 = es.get("class4"); cat = es.get("category")
    if c4: err_cls[c4] += 1
    if cat: err_cat[cat] += 1
    ts = r.get("timestamp") or ""
    if ts: hourly[ts[:13]] += 1
    task_c[r.get("task_id") or "?"] += 1
    type_c[r.get("question_type") or "?"] += 1
    if r.get("flag"): success += 1
    retries_sum += r.get("retries") or 0
stats["goal_log"] = {
    "rows": len(gl_rows),
    "success_rows": success,
    "error_class4": dict(err_cls.most_common()),
    "error_cat": dict(err_cat.most_common()),
    "hourly": dict(sorted(hourly.items())),
    "by_task": dict(task_c.most_common(12)),
    "by_type": dict(type_c.most_common()),
    "retries_sum": retries_sum,
}

# ============ 7. submitted_flags ============
sf = load_json(os.path.join(RES, "submitted_flags.json"), []) or []
stats["submitted"] = {
    "total": len(sf),
    "by_cat": dict(collections.Counter(x.get("category") for x in sf)),
    "by_id": dict(collections.Counter(x.get("challenge_id") for x in sf)),
    "first": sf[0].get("time") if sf else None,
    "last": sf[-1].get("time") if sf else None,
}

# ============ 8. 赛前答案库(answers) ============
ans = sorted(glob.glob(os.path.join(DATA, "answers", "*.txt")))
ans_cat = collections.Counter(os.path.basename(a).split("-")[0] for a in ans)
stats["answers"] = {"count": len(ans), "by_cat": dict(ans_cat.most_common())}

# ============ 9. 日志 ============
logs = []
for lf in sorted(glob.glob(os.path.join(LOGS, "*.log"))):
    logs.append({"name": os.path.basename(lf), "size": os.path.getsize(lf)})
stats["logs"] = {"count": len(logs), "total_size": sum(l["size"] for l in logs), "items": logs}

# ============ 10. 解题记录(solutions) ============
sol_py = glob.glob(os.path.join(BASE, "solutions", "*.py")) + glob.glob(os.path.join(BASE, "solutions", "legacy_tools", "*.py"))
sol_md = [os.path.basename(x) for x in glob.glob(os.path.join(BASE, "solutions", "*.md"))]
stats["solutions"] = {"py_count": len(sol_py), "writeups": sol_md}

# ============ 11. 测试 ============
tests = sorted(glob.glob(os.path.join(BASE, "tests", "test_*.py")))
stats["tests"] = {"count": len(tests), "files": [os.path.basename(t) for t in tests]}

# ============ 12. 交付物 ============
deliv = sorted(glob.glob(os.path.join(os.path.dirname(BASE), "deliverables", "*")))
dl = [os.path.basename(d) for d in deliv if os.path.isfile(d)]
stats["deliverables"] = {"count": len(dl), "items": dl}

# ============ 13. 目录规模 ============
dir_sizes = {}
for d in ("core", "agents", "ctfplatform", "skills", "scripts", "solutions", "tests", "docs"):
    p = os.path.join(BASE, d)
    if os.path.isdir(p):
        n = sum(len(fns) for _, _, fns in os.walk(p))
        dir_sizes[d] = n
stats["dir_sizes"] = dir_sizes

stats["collected_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(stats, f, ensure_ascii=False, indent=1)
print("OK ->", OUT)
print("repo files:", total, "| skills:", len(skills), "| challenges:", len(rc),
      "| race_details:", len(summ), "| goal_log:", len(gl_rows), "| answers:", len(ans))
