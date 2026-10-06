# -*- coding: utf-8 -*-
"""探查 C 类（纯数值参数）skill 对应真题的附件形态。

目的：判断「主链能否静态构造这些 skill 的入参」——若附件里的参数是可
解析的字面量（整数/hex/Python literal），则可写**确定性解析器**把 C 类
skill 也纳入 AUTO_CALLABLE；若不可靠，则维持 fail-closed 不自动调。

诚实纪律：本脚本只做形态统计，不猜参数、不调 solver。
"""
import io
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.cases import load_questions  # noqa: E402
from core.prompts import infer_skill_require  # noqa: E402
from tools.skill_manager import SkillManager  # noqa: E402

TARGETS = [
    "crypto_cycling", "crypto_primes_subset", "crypto_knapsack_mhk",
    "crypto_electric_mayhem_cls", "crypto_pkcs1_padding_oracle",
    "crypto_complex_mult_group",
]


def _load_all():
    """聚合同步内is_true题库 + 外部池，一眼看全 C 类 skill 的覆盖面。"""
    out = []
    seen = set()
    for fn in (lambda: load_questions("data/questions"),
               lambda: load_questions("data/questions_real"),
               lambda: load_questions("data/questions_external")):
        try:
            qs = fn()
        except Exception:
            continue
        for q in qs or []:
            key = getattr(q, "id", None) or getattr(q, "title", None)
            if key in seen:
                continue
            seen.add(key)
            out.append(q)
    return out


def main():
    qs = _load_all()
    print("题库总数: %d" % len(qs))
    sm = SkillManager()
    try:
        sm.discover()
    except Exception as e:  # noqa: BLE001
        print("discover fail: %s" % e)
    hits = {t: [] for t in TARGETS}
    for q in qs:
        ctx = SimpleNamespace(question=q)
        reflection = {"ability_gap": ["<probe>"]}
        try:
            req = infer_skill_require(ctx, reflection, skill_manager=sm)
        except Exception as e:  # noqa: BLE001
            print("route fail: %s" % e)
            req = None
        if not req:
            continue
        name = req.get("skill_name") if isinstance(req, dict) else None
        if name in hits:
            hits[name].append(q)

    for t in TARGETS:
        print("\n" + "=" * 72)
        print("### %s  ->  命中 %d 题" % (t, len(hits[t])))
        for q in hits[t]:
            print("-" * 60)
            print("id=%s  title=%r" % (getattr(q, "id", "?"),
                                       getattr(q, "title", "")[:60]))
            atts = getattr(q, "attachments", None) or []
            if isinstance(atts, str):
                atts = [atts]
            for a in atts:
                p = str(a)
                exists = os.path.isfile(p)
                size = os.path.getsize(p) if exists else -1
                print("  附件: %s  exists=%s size=%s" % (p, exists, size))
                if exists and size > 0 and size < 300000:
                    try:
                        with io.open(p, "r", encoding="utf-8",
                                     errors="replace") as fh:
                            head = fh.read(700)
                    except OSError as e:
                        print("     读取失败: %s" % e)
                        continue
                    print("    ---- 前 700 字符 ----")
                    for line in head.splitlines()[:22]:
                        print("      | " + line[:150])
            if not atts:
                print("  (无附件)")


if __name__ == "__main__":
    main()
