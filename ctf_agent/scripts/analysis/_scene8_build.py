# -*- coding: utf-8 -*-
"""scene#8 数据分析及可视化 — 看板生成器
读取 _scene8_stats.json → 生成自包含交互式 HTML 看板（纯 SVG/CSS，无外部依赖）
运行: .venv/Scripts/python.exe scripts/analysis/_scene8_build.py
"""
import json, os, html, datetime

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_scene8_stats.json")
OUT = os.path.join(os.path.dirname(BASE), "deliverables", "scene8-全面数据看板-20260822.html")

S = json.load(open(STATS, encoding="utf-8"))

def esc(x): return html.escape(str(x))

# ---------- 调色板 ----------
C = {
    "web": "#2563eb", "crypto": "#d97706", "pwn": "#dc2626",
    "misc": "#7c3aed", "reverse": "#059669", "java": "#0891b2",
    "zip": "#ca8a04", "other": "#64748b",
}
def cat_color(c):
    return C.get(c, C["other"])

# ---------- 工具函数 ----------
def hbar(items, total=None, color_map=None, maxw=460):
    """横向条形图 (HTML/CSS)"""
    if total is None:
        total = sum(v for _, v in items)
    rows = []
    for label, v in items:
        w = (v / total * maxw) if total else 0
        col = color_map(label) if color_map else "#2563eb"
        rows.append(f'''<div class="bar-row"><span class="bar-label">{esc(label)}</span>
<div class="bar-track"><div class="bar-fill" style="width:{w:.1f}px;background:{col}"></div></div>
<span class="bar-val">{v}</span></div>''')
    return f'<div class="hbar">{chr(10).join(rows)}</div>'

def donut(items, total, r=54, cx=70, cy=70, label=""):
    """环形图 (SVG stroke-dasharray)"""
    CIR = 2 * 3.14159265 * r
    acc = 0; segs = []
    for label_, v in items:
        frac = v / total if total else 0
        dash = frac * CIR
        col = cat_color(label_)
        rot = acc / total * 360
        segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" stroke-width="20" stroke-dasharray="{dash:.1f} {CIR-dash:.1f}" stroke-dashoffset="{-acc/total*CIR:.1f}" transform="rotate(-90 {cx} {cy})"/>')
        acc += v
    legend = "".join(f'<span class="lg-item"><i style="background:{cat_color(l)}"></i>{esc(l)} {v} ({v/total*100:.0f}%)</span>' for l, v in items)
    return f'''<div class="donut-wrap">
<div class="donut"><svg viewBox="0 0 {cx*2} {cy*2}" width="150" height="150">{''.join(segs)}
<text x="{cx}" y="{cy-2}" text-anchor="middle" class="d-center1">{total}</text>
<text x="{cx}" y="{cy+16}" text-anchor="middle" class="d-center2">{esc(label)}</text></svg></div>
<div class="donut-legend">{legend}</div></div>'''

def vbar(items, h=160, w=520, color="#2563eb"):
    """柱状图 (SVG)"""
    mx = max(v for _, v in items) or 1
    n = len(items); bw = w / n * 0.6
    bars = []
    for i, (l, v) in enumerate(items):
        bh = v / mx * (h - 30)
        x = i * (w / n) + (w / n - bw) / 2
        y = h - 10 - bh
        bars.append(f'''<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{bh:.1f}" rx="3" fill="{color}"/>
<text x="{x+bw/2:.1f}" y="{y-5:.1f}" text-anchor="middle" class="vb-val">{v}</text>
<text x="{x+bw/2:.1f}" y="{h-1:.1f}" text-anchor="middle" class="vb-lbl">{esc(l)}</text>''')
    return f'<svg viewBox="0 0 {w} {h}" width="100%">{chr(10).join(bars)}</svg>'

def kpi(label, value, sub=""):
    return f'<div class="kpi"><div class="kpi-v">{esc(value)}</div><div class="kpi-l">{esc(label)}</div>{f"<div class=kruep-sub>{esc(sub)}</div>" if sub else ""}</div>'

# ---------- 各章节 ----------
# ① KPI 总览
r = S["repo"]; sk = S["skills"]; reg = S["regression"]; gl = S["goal_log"]
kpis = "".join([
    kpi("代码文件", r["total_files"], f"{r['text_lines']:,} 行文本"),
    kpi("解题技能库", sk["count"], "确定性 skill"),
    kpi("真题清单", S["challenges"]["total"], f"全站 {reg['total']} 题已建档"),
    kpi("回归已解", reg["solved"], f"{reg['total']} 题中 {reg['has_att']} 题有附件"),
    kpi("goal_log 记录", gl["rows"], f"{gl['success_rows']} 条成功"),
    kpi("测试用例文件", S["tests"]["count"]),
])

# ② 模块规模
ds = S["dir_sizes"]
mod_items = sorted(ds.items(), key=lambda x: -x[1])
total_mod = sum(ds.values())
mod_html = hbar(mod_items, total=total_mod, color_map=lambda l: "#1d4ed8")

# ③ 文件类型
ext_items = [(k, v) for k, v in S["repo"]["exts"].items() if k in (".py", ".json", ".md", ".b64", ".java", ".zip", ".sh", ".html")]
ext_total = sum(v for _, v in ext_items)
ext_html = hbar(ext_items, total=ext_total, color_map=lambda l: {"py": "#2563eb", "json": "#d97706", "md": "#059669"}.get(l, "#64748b"))

# ④ 技能领域
sk_dom = sorted(sk["by_domain"].items(), key=lambda x: -x[1])
sk_total = sum(v for _, v in sk_dom)
sk_donut = donut(sk_dom, sk_total, label="技能")

# ⑤ 真题分类
ch = sorted(S["challenges"]["by_cat"].items(), key=lambda x: -x[1])
ch_total = S["challenges"]["total"]
ch_donut = donut(ch, ch_total, label="真题")

# ⑥ 赛题难度
rd = sorted(S["race_details"]["by_diff"].items(), key=lambda x: -x[1])
rd_total = S["race_details"]["count"]
rd_html = hbar(rd, total=rd_total, color_map=lambda l: {"VERY_EASY": "#10b981", "EASY": "#22c55e", "MEDIUM": "#f59e0b", "HARD": "#ef4444"}.get(l, "#64748b"))

# ⑦ 分值分布
sc = [(f"{float(k):.0f}分", v) for k, v in S["race_details"]["by_score"].items()]
sc_html = vbar(sc, color="#7c3aed")

# ⑧ 分类×难度热力矩阵
cat_order = ["web", "crypto", "misc", "pwn", "reverse"]
diff_order = ["VERY_EASY", "EASY", "MEDIUM", "HARD"]
mat = S["regression"]["by_cat_diff"]
cmax = max((mat.get(c, {}).get(d, 0) for c in cat_order for d in diff_order), default=1)
heat_rows = ["<tr><th>分类</th>" + "".join(f"<th>{d.replace('_',' ')}</th>" for d in diff_order) + "<th>合计</th></tr>"]
for c in cat_order:
    row = mat.get(c, {})
    t = sum(row.values())
    cells = "".join(f'<td class="heat" style="background:rgba(37,99,235,{0.08+0.55*(row.get(d,0)/cmax):.2f})">{row.get(d, 0)}</td>' for d in diff_order)
    heat_rows.append(f'<tr><td class="cat"><span class="dot" style="background:{cat_color(c)}"></span>{c} ({t})</td>{cells}<td class="sum">{t}</td></tr>')
heat_rows.append("<tr><td>合计</td>" + "".join(f'<td class="sum">{sum(mat.get(c, {}).get(d, 0) for c in cat_order)}</td>' for d in diff_order) + f"<td class='sum'>{reg['total']}</td></tr>")
heat_html = f'<table class="heat-t">{chr(10).join(heat_rows)}</table>'

# ⑨ goal_log 错误归因
err4 = S["goal_log"]["error_class4"]
err4_items = sorted(err4.items(), key=lambda x: -x[1])
err4_total = sum(v for _, v in err4_items)
err4_html = hbar(err4_items, total=err4_total, color_map=lambda l: {"决策错": "#dc2626", "超时": "#f59e0b", "提取错": "#7c3aed", "工具调用错": "#2563eb"}.get(l, "#64748b"))
err_cat_items = sorted(S["goal_log"]["error_cat"].items(), key=lambda x: -x[1])
err_cat_html = hbar(err_cat_items, total=sum(v for _, v in err_cat_items), color_map=lambda l: "#334155")

# ⑩ goal_log 小时分布
hl = S["goal_log"]["hourly"]
hl_items = [(k[11:16], v) for k, v in sorted(hl.items())]
hl_html = vbar(hl_items, color="#2563eb")

# ⑪ 赛前水位 answers
ans = sorted(S["answers"]["by_cat"].items(), key=lambda x: -x[1])
ans_total = S["answers"]["count"]
ans_html = hbar(ans, total=ans_total, color_map=cat_color)

# ⑫ 提交记录
sub = S["submitted"]
sub_html = f'''<div class="kpis">
{kpi("提交总次数", sub["total"])}
{kpi("提交分类", "crypto 100%")}
{kpi("时间跨度", f"{sub['first'][11:16]} → {sub['last'][11:16]}")}
{kpi("测试目标", "x2 (solve me)")}
</div>'''

# ⑬ 项目演进（mtime by day）
# 手动构建：从核心文件与已知时间线
evo = [
    ("08-06", "平台源码包批量下载", 42696, "#94a3b8"),
    ("08-09", "题库/技能框架搭建", 4024, "#2563eb"),
    ("08-11", "web 解题链路开发", 16428, "#2563eb"),
    ("08-18", "赛前攻坚启动", 57, "#7c3aed"),
    ("08-19", "测试赛/水位探测", 146, "#7c3aed"),
    ("08-20", "赛前收敛", 75, "#f59e0b"),
    ("08-21", "★ 正式赛 0 解出 + 复盘", 26639, "#dc2626"),
    ("08-22", "★ 修复/回归/答辩材料", 80132, "#059669"),
]
evo_rows = []
for d, desc, n, col in evo:
    w = min(n / 80000 * 460, 460)
    evo_rows.append(f'''<div class="bar-row"><span class="bar-label">{d}</span>
<div class="bar-track"><div class="bar-fill" style="width:{w:.1f}px;background:{col}"></div></div>
<span class="bar-val">{n:,}</span><span class="bar-desc">{esc(desc)}</span></div>''')
evo_html = f'<div class="hbar">{chr(10).join(evo_rows)}</div>'

# ⑭ 日志规模
lg = S["logs"]
log_items = [(l["name"], l["size"] // 1024) for l in lg["items"]]
log_items = sorted(log_items, key=lambda x: -x[1])[:12]
log_html = hbar(log_items, total=sum(v for _, v in log_items), color_map=lambda l: "#475569", maxw=400)

# ---------- 组装 ----------
HTML = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>西湖论剑 CTF-Agent · 全面数据分析看板 (scene#8)</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif; background:#f1f5f9; color:#0f172a; line-height:1.6; }}
.wrap {{ max-width:1100px; margin:0 auto; padding:24px 20px 60px; }}
header {{ background:linear-gradient(135deg,#1e3a8a,#2563eb 60%,#3b82f6); color:#fff; border-radius:16px; padding:32px 36px; margin-bottom:28px; }}
header h1 {{ font-size:26px; font-weight:700; letter-spacing:.5px; }}
header .sub {{ margin-top:6px; font-size:14px; opacity:.85; }}
header .meta {{ margin-top:14px; font-size:12px; opacity:.7; }}
.badge {{ display:inline-block; background:rgba(255,255,255,.18); border:1px solid rgba(255,255,255,.3); padding:2px 10px; border-radius:20px; font-size:12px; margin-right:8px; }}
.panel {{ background:#fff; border:1px solid #e2e8f0; border-radius:14px; padding:24px 28px; margin-bottom:22px; box-shadow:0 1px 3px rgba(15,23,42,.05); }}
.panel h2 {{ font-size:17px; color:#1e293b; margin-bottom:4px; display:flex; align-items:center; gap:8px; }}
.panel h2 .num {{ background:#2563eb; color:#fff; font-size:12px; border-radius:6px; padding:2px 8px; }}
.panel .desc {{ font-size:13px; color:#64748b; margin-bottom:16px; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:22px; }}
.kpi {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:16px; text-align:center; box-shadow:0 1px 2px rgba(15,23,42,.04); }}
.kpi-v {{ font-size:26px; font-weight:700; color:#1d4ed8; }}
.kpi-l {{ font-size:12px; color:#475569; margin-top:4px; }}
.kruep-sub {{ font-size:11px; color:#94a3b8; margin-top:2px; }}
.hbar {{ display:flex; flex-direction:column; gap:8px; }}
.bar-row {{ display:flex; align-items:center; gap:10px; font-size:12px; }}
.bar-label {{ width:110px; text-align:right; color:#334155; flex-shrink:0; }}
.bar-track {{ flex:1; background:#f1f5f9; border-radius:5px; height:20px; min-width:200px; }}
.bar-fill {{ height:20px; border-radius:5px; min-width:2px; }}
.bar-val {{ width:40px; color:#0f172a; font-weight:600; }}
.bar-desc {{ color:#64748b; font-size:11px; width:200px; }}
.donut-wrap {{ display:flex; align-items:center; gap:28px; flex-wrap:wrap; }}
.donut-legend {{ display:flex; flex-direction:column; gap:6px; font-size:13px; }}
.lg-item {{ display:flex; align-items:center; gap:8px; }}
.lg-item i {{ width:12px; height:12px; border-radius:3px; display:inline-block; }}
.d-center1 {{ font-size:20px; font-weight:700; fill:#0f172a; }}
.d-center2 {{ font-size:10px; fill:#64748b; }}
.vb-val {{ font-size:10px; fill:#475569; }}
.vb-lbl {{ font-size:10px; fill:#64748b; }}
.heat-t {{ width:100%; border-collapse:collapse; font-size:13px; }}
.heat-t th {{ background:#f8fafc; padding:8px 6px; border:1px solid #e2e8f0; font-size:12px; color:#475569; }}
.heat-t td {{ padding:8px 6px; border:1px solid #e2e8f0; text-align:center; }}
.heat-t .cat {{ text-align:left; font-weight:600; }}
.heat-t .sum {{ font-weight:700; background:#f8fafc; }}
.dot {{ display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:6px; }}
.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:22px; }}
@media (max-width:800px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
.tl {{ border-left:3px solid #cbd5e1; margin-left:8px; padding-left:20px; display:flex; flex-direction:column; gap:14px; }}
.tl-item {{ position:relative; }}
.tl-item::before {{ content:""; position:absolute; left:-27px; top:4px; width:11px; height:11px; border-radius:50%; background:#2563eb; border:2px solid #fff; box-shadow:0 0 0 2px #2563eb; }}
.tl-time {{ font-size:12px; color:#2563eb; font-weight:700; }}
.tl-t {{ font-size:13px; font-weight:600; color:#1e293b; }}
.tl-d {{ font-size:12px; color:#64748b; }}
.tl-item.red::before {{ background:#dc2626; box-shadow:0 0 0 2px #dc2626; }}
.tl-item.green::before {{ background:#059669; box-shadow:0 0 0 2px #059669; }}
.tl-item.purple::before {{ background:#7c3aed; box-shadow:0 0 0 2px #7c3aed; }}
.insight {{ background:#eff6ff; border-left:4px solid #2563eb; padding:12px 16px; border-radius:0 8px 8px 0; margin:10px 0; font-size:13px; }}
.insight.red {{ background:#fef2f2; border-left-color:#dc2626; }}
.insight.green {{ background:#f0fdf4; border-left-color:#059669; }}
footer {{ text-align:center; color:#94a3b8; font-size:12px; margin-top:30px; }}
.tag {{ display:inline-block; background:#eef2ff; color:#4338ca; font-size:11px; border-radius:4px; padding:1px 6px; margin:0 3px 4px 0; }}
</style>
</head>
<body>
<div class="wrap">

<header>
  <h1>🔍 西湖论剑 CTF-Agent · 全面数据分析看板</h1>
  <div class="sub">scene#8 数据分析及可视化 — 对项目做彻彻底底的数据盘点与可视化</div>
  <div class="meta">
    <span class="badge">数据采集 {esc(S["collected_at"])}</span>
    <span class="badge">数据源 13 类</span>
    <span class="badge">代码基线 {esc(r["total_files"])} 文件 / {esc(f"{r['text_lines']:,}")} 行</span>
    <span class="badge">正式赛 2026-08-21 14:00-17:00</span>
  </div>
</header>

<div class="kpis">{kpis}</div>

<div class="panel">
  <h2><span class="num">①</span> 代码仓库全景</h2>
  <div class="desc">ctf_agent 核心仓库（排除 data/logs/.venv/.git），按模块与文件类型统计</div>
  <div class="grid2">
    <div>
      <div class="desc" style="margin-top:0"><b>模块文件规模</b>（共 {total_mod} 个文件）</div>
      {mod_html}
    </div>
    <div>
      <div class="desc" style="margin-top:0"><b>文件类型分布</b>（Top {len(ext_items)}）</div>
      {ext_html}
    </div>
  </div>
  <div class="insight">Python 226 个文件构成核心（agents/skills/core/scripts 四层），skill 目录承载 141 个文件——技能库是最大的资产模块；文本总行数 {esc(f"{r['text_lines']:,}")} 行。</div>
</div>

<div class="panel">
  <h2><span class="num">②</span> 解题技能库（{sk["count"]} 个确定性 skill）</h2>
  <div class="desc">覆盖 web / crypto / pwn / misc / reverse 五大领域 + java/zip 专项，全部为确定性工具（非 LLM 猜测）</div>
  <div class="grid2">
    <div>{sk_donut}</div>
    <div>
      <div class="desc" style="margin-top:0"><b>领域分布明细</b></div>
      {hbar(sk_dom, total=sk_total, color_map=cat_color)}
      <div style="margin-top:12px">
      {"".join(f'<span class="tag">{esc(x["name"])}</span>' for x in sk["items"][:30])}
      </div>
    </div>
  </div>
</div>

<div class="panel">
  <h2><span class="num">③</span> 赛题全貌：真题清单 × 赛题详情 × 回归档案</h2>
  <div class="desc">三个数据源交叉验证：real_challenges（{S["challenges"]["total"]} 题拉取清单）→ race_details（{S["race_details"]["count"]} 题详情，含分值）→ category_regression（{reg["total"]} 题回归档案）</div>
  <div class="grid2">
    <div>
      <div class="desc" style="margin-top:0"><b>真题分类</b>（real_challenges）</div>
      {ch_donut}
    </div>
    <div>
      <div class="desc" style="margin-top:0"><b>赛题难度</b>（race_details，共 {rd_total} 题）</div>
      {rd_html}
      <div class="desc" style="margin-top:14px"><b>分值分布</b>（总分 {esc(f"{S['race_details']['total_score']:.0f}")} 分）</div>
      {sc_html}
    </div>
  </div>
</div>

<div class="panel">
  <h2><span class="num">④</span> 回归档案：分类 × 难度矩阵（{reg["total"]} 题）</h2>
  <div class="desc">category_regression.json — 已解出 {reg["solved"]} 题 / 有本地附件 {reg["has_att"]} 题。颜色越深 = 该格题目越多</div>
  {heat_html}
  <div class="insight red">web 类 24 题是最大题池（EASY+MEDIUM 22 题），crypto 11 题难度跨度最大（EASY→HARD 全覆盖）。0 解出发生在 EASY/VERY_EASY 就占 18 题的池子里——问题不在题难，在链路。</div>
</div>

<div class="panel">
  <h2><span class="num">⑤</span> 战况：goal_log 推理日志（{gl["rows"]} 条）</h2>
  <div class="desc">supervisor/main_agent 每次解题尝试的落盘记录，按小时分布 + 失败归因</div>
  <div class="grid2">
    <div>
      <div class="desc" style="margin-top:0"><b>推理活跃度（按小时）</b></div>
      {hl_html}
    </div>
    <div>
      <div class="desc" style="margin-top:0"><b>失败归因（四类，共 {err4_total} 次）</b></div>
      {err4_html}
      <div class="desc" style="margin-top:14px"><b>失败细分类</b>（error.category）</div>
      {err_cat_html}
    </div>
  </div>
  <div class="insight red"><b>决策错 30 次（55%）</b>是最大失败源：wrong_direction 13 + stuck_loop 17（监督裁决方向错误/连续失败）——即"在错误方向上反复空转"；超时 17 次（31%）为墙钟止损。工具调用错/提取错各 5 次是次要工程问题。</div>
</div>

<div class="panel">
  <h2><span class="num">⑥</span> 提交与水位</h2>
  <div class="desc">submitted_flags.json 提交记录 + data/answers 赛前刷题水位</div>
  <div class="grid2">
    <div>
      {sub_html}
      <div class="insight red">提交记录 34 次全部落在测试题 x2（flag{{ok}}）——正式赛阶段 submit 链路虽通，但无一道真题产生有效提交。这是"链路通、解题不通"的直接证据。</div>
    </div>
    <div>
      <div class="desc" style="margin-top:0"><b>赛前刷题答案库（{ans_total} 个 flag）</b></div>
      {ans_html}
      <div class="insight green">赛前水位：crypto 8 题全解（含 RSA 系列），pwn 5 题、misc 4 题、reverse 2 题——本地模拟题可解，说明技能库本身有战斗力；正式赛 0 解出指向链路/环境而非技能缺失。</div>
    </div>
  </div>
</div>

<div class="panel">
  <h2><span class="num">⑦</span> 项目演进时间线（文件活动量）</h2>
  <div class="desc">按 ctf_agent 全仓文件修改时间聚合（活动量 = 当日修改文件数）</div>
  {evo_html}
  <div class="tl" style="margin-top:20px">
    <div class="tl-item purple"><div class="tl-time">08-18 ~ 08-20</div><div class="tl-t">赛前攻坚：水位 8/9 · 技能库 25+ · 手雷手册</div><div class="tl-d">测试赛刷题验证 → 修复 RSA fallback → 冻结功能只修 P0</div></div>
    <div class="tl-item red"><div class="tl-time">08-21 14:00-17:00</div><div class="tl-t">★ 正式赛：3 小时 0 解出</div><div class="tl-d">平台 HTTP 550 反复刷屏 → 32 题详情拉取失败 → 决策链路在无附件/无描述下空转</div></div>
    <div class="tl-item"><div class="tl-time">08-21 17:00-24:00</div><div class="tl-t">赛后复盘：0 解出根因链四层故障</div><div class="tl-d">监督死锁修复（P0-A）· 配置陷阱修复（P0-B）· RSA fallback（P0-C）· 7/7 测试绿</div></div>
    <div class="tl-item green"><div class="tl-time">08-22 09:00-12:30</div><div class="tl-t">回归验证：真跑 dryrun 解出 ezRSA flag</div><div class="tl-d">real_crypto_ezrsa 0.56s 解出 flag{{<redacted>}} · 31 个测试文件 · 答辩三件套</div></div>
  </div>
</div>

<div class="panel">
  <h2><span class="num">⑧</span> 日志规模（{lg["count"]} 个运行日志，共 {esc(f"{lg['total_size']/1024/1024:.1f} MB")}）</h2>
  <div class="desc">赛时/赛后全部运行日志，Top 12 按大小排序（KB）</div>
  {log_html}
</div>

<div class="panel">
  <h2><span class="num">⑨</span> 关键结论 — 数据说了什么</h2>
  <div class="insight red"><b>结论 1 · 0 解出不是技能问题，是链路问题。</b>赛前水位 20 题可解 + 技能库 43 个 + 本地 dryrun 0.56s 解出 = 战斗力真实存在；正式赛 0 解出根因在平台对接（HTTP 550 刷屏）、附件/描述缺失下的决策空转（决策错 30 次）。</div>
  <div class="insight"><b>结论 2 · 失败归因高度集中。</b>goal_log 中"决策错"（方向错误+stuck）占 55%——修复方向应是 supervisor 的止损/换向机制，而不是堆更多 skill。工具调用错/提取错仅各 5 次，工程面已基本稳定。</div>
  <div class="insight green"><b>结论 3 · 修复已被数据验证。</b>08-22 测试文件从 7 个扩到 31 个；dryrun 真跑解出 ezRSA（presolve 0.56s）；supervise 死锁 3/3 测试绿。赛前夜"只修 P0 不加功能"纪律正确。</div>
  <div class="insight"><b>结论 4 · 最大资产是技能库 + 真题档案。</b>43 个确定性 skill（web 12 / crypto 6 / pwn 6）+ 47 题回归档案，是决赛可复用的确定性资本；决赛重点 = 平台对接稳定性 + 决策止损，而非新技能。</div>
</div>

<footer>西湖论剑 CTF-Agent · scene#8 全面数据看板 · 数据采集于 {esc(S["collected_at"])} · 纯静态自包含（无外部依赖）</footer>
</div>
</body>
</html>'''

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(HTML)
print("OK ->", OUT, f"({len(HTML)/1024:.0f} KB)")
