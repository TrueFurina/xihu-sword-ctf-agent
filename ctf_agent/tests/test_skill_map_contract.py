"""skill_map 静态性质守卫 —— 纯源码/目录检查，**零真题依赖**。

背景（本文件的由来，2026-10-08）
--------------------------------
审计 xihu 门禁脱管时逐行读了 5 个 route 测试文件，发现它们被标 `@pytest.mark.local`
的**唯一原因**是一行 `qj["description"]` —— 而 `infer_skill_require` 只做
`ctx.question.description` 的字符串 `in` 匹配，并不触碰 `data/` 下任何文件。

**但「把描述内联进测试」是错的改法**：`infer_skill_require` 的逻辑就是遍历
`skill_map` 做 `in` 匹配，给定 (skill_map, 输入串) 输出确定。
自造输入 = 验证「我设的键存在于字面量里」= 循环论证 = 空断言，
而且与同文件已有的 `assertIn('"2^1025": "crypto_cycling"', PROMPTS_SRC)`
完全重复。⇒ 路由测试留在 local 是**对的**，不动。

本文件改为补一条**真正缺失**的守卫：`prompts.py` 自己的 docstring 声明了两条
硬规则，但**没有任何测试在守**：

  1. 「映射表只允许引用 skills/ 目录真实存在的 skill；本地有→加载，本地无→返回 None」
     —— 一旦有人往skill_map 里写了个不存在的 skill 名，
     `infer_skill_require` 会走到 `mgr.load(name)` 分支，
     线上表现为**该题永远路由不到任何 solver、且不报错**（静默失效）。
  2. 「去重：删除重复键（Python dict 字面量重复键静默覆盖，前面的映射是死代码）」
     —— 2026-08-22 确实修过一次，但**没有回归守卫**，随时可能再犯。

为什么这类检查价值高：它验的是**接线契约**，不是解题能力。
本仓库 `mark.local` 共 38 处（1383 个测试函数里），全部是「依赖真题/附件」的
真实能力护栏；接线类护栏**本就该在 CI 上常驻**。
"""
import ast
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CTF = os.path.abspath(os.path.join(_HERE, ".."))
PROMPTS_PATH = os.path.join(_CTF, "core", "prompts.py")
SKILLS_DIR = os.path.join(_CTF, "skills")


def _read_prompts_src() -> str:
    with open(PROMPTS_PATH, encoding="utf-8") as _f:
        return _f.read()


def _skill_map_node():
    """返回 skill_map 的 ast.Dict 节点（而非 literal_eval 的结果）。

    刻意不用 ``ast.literal_eval``：它会把重复键**静默折叠**成最后一个，
    那样我们最想抓的那类退化恰好被工具掩盖掉。
    """
    tree = ast.parse(_read_prompts_src())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "skill_map":
                    assert isinstance(node.value, ast.Dict), (
                        "skill_map 应保持为字面量 dict；若改成运行时构造，"
                        "本守卫会失去覆盖 —— 请同步更新本文件并说明理由")
                    return node.value
    raise AssertionError("skill_map not found in prompts.py")


def _real_skill_names():
    """skills/ 目录下真实存在的 solver 模块名（不含 __init__）。"""
    if not os.path.isdir(SKILLS_DIR):
        return set()
    return {
        fn[:-3]
        for fn in os.listdir(SKILLS_DIR)
        if fn.endswith(".py") and fn != "__init__.py"
    }


class TestSkillMapStaticContract(unittest.TestCase):
    """skill_map 的静态性质。全部只读 prompts.py 与 skills/ 目录。"""

    def test_skill_map_is_static_literal(self):
        """skill_map 必须是字面量 —— 否则下列所有静态检查都失效。"""
        self.assertIsNotNone(_skill_map_node())

    def test_no_dangling_skill_reference(self):
        """每个映射目标必须对应 skills/ 下真实存在的 solver。

        违反后果（静默失效）：`infer_skill_require` 认定该skill 可用后
        调`mgr.load(name)`，而加载会失败/找不到 ⇒ 题目路由不到任何求解器，
        不抛异常、不留痕迹 —— 与2026-10-06 那起「孤儿求解器」同类，
        但更隐蔽：连 skill_map 里有这个键都看不出来。
        """
        node = _skill_map_node()
        real = _real_skill_names()
        self.assertTrue(real, "skills/ 目录为空或不存在，无法校验映射")
        # ⚠️ 必须取 .values()：直接迭代 ast.literal_eval(node) 得到的是**键**，
        #    会把全部 200 个键误报成悬空 skill。
        dangling = sorted({
            v for v in ast.literal_eval(node).values()
            if isinstance(v, str) and v not in real
        })
        self.assertEqual(
            dangling, [],
            "skill_map 指向 skills/ 下不存在的 skill：%s"
            "（要么拼错，要么该 solver 被删/改名 —— "
            "后者必须连同 skill_map 的键一起清理）" % dangling)

    def test_no_duplicate_keys(self):
        """同一字面量内不得有重复键（后者静默覆盖前者 ⇒ 前者是死代码）。

        ⚠️ 不能用 ``ast.literal_eval`` 检查：它把重复键折叠成最后一个，
        恰好掩盖本用例要抓的退化。2026-08-22 的锐评修复过这个，
        但一直没有守卫 —— 今天补上。
        """
        node = _skill_map_node()
        seen = set()
        dups = []
        for k in node.keys:
            if not isinstance(k, ast.Constant):
                continue
            if k.value in seen:
                dups.append(k.value)
            seen.add(k.value)
        self.assertEqual(
            dups, [],
            "skill_map 有重复键 %s：Python dict 字面量会静默保留最后一个，"
            "前面的映射是死代码（读代码时看不见，运行也用不到）" % sorted(set(dups)))

    def test_literal_eval_agrees_with_raw_keys(self):
        """交叉验证：字面量求值结果与原始键列表的**长度**一致。

        这条是给上面两条兜底的：若哪天`skill_map` 的结构变了
        （变成拼接、推导、含非字面量键），前两条会静默失效，
        本条通过长度不一致把「守卫本身失效」暴露成一次红。
        """
        node = _skill_map_node()
        raw_const_keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
        self.assertEqual(
            len(ast.literal_eval(node)), len(set(raw_const_keys)),
            "literal_eval 结果与原始键数不一致 —— skill_map 结构可能已改变，"
            "本文件的静态守卫需要重新评估")


class TestSkillMapRoutingHygiene(unittest.TestCase):
    """键序纪律：命中即return，所以「专属键必须排在通用键之前」是硬要求。

    ⚠️ 判据必须收窄到「遮蔽后指向**不同** solver」。
    最初版本判「前面的键是后面键的子串」就失败，误报 23 处
    （`rsa`/`rsa脚本`、`zip`/`zip密码` 等**同 solver 的等价别名**——
    行为完全一致，不构成缺陷）。
    只有跨 solver 的遮蔽才是真问题：它让一个 solver 彻底失去入口。
    """

    def _pairs(self):
        node = _skill_map_node()
        return [
            (k.value, v.value)
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)
            and isinstance(k.value, str) and isinstance(v.value, str)
        ]

    def test_no_shadowed_key_points_to_different_solver(self):
        """被更早的键遮蔽、且指向不同 solver ⇒ 该键永远不会被命中。

        机制：`infer_skill_require` 按 skill_map 键序遍历、`in` 匹配、**命中即 return**。
        若通用键 `'zip'` 排在专用的 `'zip_filename'` 之前，
        则任何含 "zip" 的题面都先命中 `zip_chain_decode`，
        `zip_filename_chain_decode` 再也拿不到路由。

        实测（2026-10-08，main = 9608f87fad）8 处这样的死键，
        其中 `zip_filename_chain_decode` 的 3 个专用键全部被遮蔽，
        只剩 `伪加密` 一个窄入口 —— 而多层 zip 套娃正是靠文件名链解出来的。
        本用例锁住该纪律，防止再次因调键序而静默丢失解题能力。
        """
        pairs = self._pairs()
        self.assertTrue(pairs, "未解析到任何 skill_map 键值对")
        shadowed = []
        for i, (k1, v1) in enumerate(pairs):
            lk1 = k1.lower()
            for j in range(i + 1, len(pairs)):
                k2, v2 = pairs[j]
                if k1 != k2 and lk1 in k2.lower() and v1 != v2:
                    shadowed.append((k1, v1, k2, v2))
        self.assertEqual(
            [s[2] for s in shadowed], [],
            "以下键被更早的键遮蔽、永不可达（infer_skill_require 命中即 return）：\n"
            + "\n".join(
                "  键 %r (-> %s) 排在 %r (-> %s) 之前 ⇒ %r 永远不会被命中"
                % (k1, v1, k2, v2, k2)
                for k1, v1, k2, v2 in shadowed)
            + "\n\n解法：把更具体的键上移（专属键必须排在通用键之前），"
              "或删除被遮蔽的冗余键。")

    def test_shadowing_is_detectable_at_all(self):
        """兜底：确认本文件真能检出遮蔽（防止守卫退化成空断言）。

        用构造的最小 skill_map 跑同一判据，断言它能抓到已知的遮蔽形态。
        """
        pairs = [("zip", "zip_chain_decode"), ("zip_filename", "other_solver")]
        shadowed = [
            (k1, k2) for i, (k1, v1) in enumerate(pairs)
            for (k2, v2) in pairs[i + 1:]
            if k1 != k2 and k1.lower() in k2.lower() and v1 != v2
        ]
        self.assertEqual(shadowed, [("zip", "zip_filename")],
                         "遮蔽判据本身失效 —— 上面的守卫会变成空断言")


if __name__ == "__main__":
    unittest.main(verbosity=2)
