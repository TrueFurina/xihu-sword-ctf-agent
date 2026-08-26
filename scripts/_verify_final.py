"""最终验证：确认 benchmark_real.json 中全部题目解出。"""
import json
import os

p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "data", "results", "benchmark_real.json")
d = json.load(open(p, encoding="utf-8"))
r = d["results"]
s = d["summary"]

print(f"总计: {s['total']} 题")
print(f"已解: {s['solved']} 题")
print(f"解出率: {s['solve_rate']*100:.1f}%")
print()

unsolved = [k for k, v in r.items() if not (v.get("flag") and v.get("validated"))]
if unsolved:
    print(f"❌ 未解出 {len(unsolved)} 题:")
    for k in unsolved:
        v = r[k]
        print(f"  - {k}: flag={v.get('flag')}, validated={v.get('validated')}")
else:
    print("✅ ALL 29/29 SOLVED!")

print()
print("之前失败的 11 题验证:")
keys = ["web-001","web-002","web-003","web-005","web-006","web-007",
        "misc-003","misc-006","misc-008","crypto-004","pwn-005"]
for k in keys:
    v = r.get(k, {})
    flag = v.get("flag", "MISSING")
    ok = v.get("validated", False)
    print(f"  {'✅' if ok else '❌'} {k}: {flag}")

print()
print("按题型汇总:")
cats = {}
for k, v in r.items():
    cat = v.get("category", k.split("-")[0])
    cats.setdefault(cat, [0, 0])
    cats[cat][0] += 1
    if v.get("flag") and v.get("validated"):
        cats[cat][1] += 1
for cat, (total, solved) in sorted(cats.items()):
    print(f"  {cat}: {solved}/{total} ({solved/total*100:.0f}%)")
