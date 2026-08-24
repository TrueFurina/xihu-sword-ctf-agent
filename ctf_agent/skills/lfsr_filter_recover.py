"""Skill: 噪声混合 LFSR 初始状态恢复（西湖论剑2021 FilterRandom）

场景：两个 64-bit LFSR（l1/l2）各自生成比特流，输出按 90%/10% 概率混合。
已知 mask1、mask2 和 2048 位混合输出，恢复 init1/init2（flag = DASCTF{init1-init2}）。

解法（2026-08-21 人工推导+实测验证）：
1. l1 占 ~90% 位：随机抽 64 个位置，用「单位向量数值构造系数矩阵」
   c_j(t) = 输出位(init=2^j 时 t 时刻) 建立 F2 线性方程 b_t = XOR_j c_j(t)*init_j，
   高斯消元解候选 init1，全量 2048 位验证匹配率 >88% 即认定（噪声位不影响）。
2. l2 占 ~10% 位：init1 预测与观测不同的位置 = l2 的真实输出位（100% 正确），
   直接在这些位置上解 l2 的线性方程即可（无需再处理噪声）。

输入: solve_lfsr_filter(mask1, mask2, out)
输出: 'DASCTF{init1-init2}' 或 None
"""


def solve_lfsr_filter(mask1, mask2, out):
    """噪声混合双 LFSR 恢复 init1/init2。"""
    import random

    LENMASK = (1 << 64) - 1

    def lfsr_next(state, mask):
        nxt = (state << 1) & LENMASK
        i = state & mask & LENMASK
        o = 0
        while i:
            o ^= (i & 1)
            i >>= 1
        nxt ^= o
        return nxt, o

    def simulate(init, mask, n):
        state = init
        bits = []
        for _ in range(n):
            state, o = lfsr_next(state, mask)
            bits.append(o)
        return bits

    def build_coeff(mask, T):
        """coeff[t][j]：init 第 j 位在 t 时刻输出的系数（init=2^j 模拟）。"""
        c = [[0] * 64 for _ in range(T)]
        for j in range(64):
            b = simulate(1 << j, mask, T)
            for t in range(T):
                c[t][j] = b[t]
        return c

    def solve_from(coeff, positions):
        """F2 高斯消元解 init（positions: (t, b) 列表）。"""
        rows = [(list(coeff[t]), b & 1) for t, b in positions]
        pivots = {}
        for x, bb in rows:
            for p in sorted(pivots):
                if x[p]:
                    x2, b2 = pivots[p]
                    for q in range(64):
                        x[q] ^= x2[q]
                    bb ^= b2
            try:
                p = next(q for q in range(64) if x[q])
            except StopIteration:
                continue
            pivots[p] = (x, bb)
        init = [0] * 64
        for p in sorted(pivots, reverse=True):
            x, b = pivots[p]
            val = b
            for q in range(p + 1, 64):
                if x[q]:
                    val ^= init[q]
            init[p] = val
        return sum(init[j] << j for j in range(64))

    obs = [int(c) for c in out.strip()]
    if len(obs) < 1024:
        return None
    C1 = build_coeff(mask1, 2048)
    random.seed(2026)
    best = None
    for trial in range(5000):
        pos = random.sample(range(2048), 64)
        cand = solve_from(C1, [(t, obs[t]) for t in pos])
        sim = simulate(cand, mask1, 2048)
        if sum(1 for a, b in zip(sim, obs) if a == b) > 1800:  # >88%
            best = cand
            break
    if best is None:
        return None
    sim1 = simulate(best, mask1, 2048)
    diff = [t for t in range(2048) if sim1[t] != obs[t]]
    if len(diff) < 64:
        return None
    C2 = build_coeff(mask2, 2048)
    for trial in range(2000):
        pos = random.sample(diff, 64)
        c2 = solve_from(C2, [(t, obs[t]) for t in pos])
        s2 = simulate(c2, mask2, 2048)
        if sum(1 for t in diff if s2[t] == obs[t]) == len(diff):
            return 'DASCTF{%d-%d}' % (best, c2)
    return None


if __name__ == "__main__":
    # 西湖论剑2021 FilterRandom 官方数据（自测）
    M1 = 17638491756192425134
    M2 = 14623996511862197922
    import re
    txt = open(r"E:/Program/Cybersecurity/比赛真题/西湖论剑2021中国杭州网络安全技能大赛/CRYPTO/FilterRandom.py", encoding="utf-8").read()
    block = txt.split("'''")[1]
    lines = [l.strip() for l in block.strip().splitlines() if l.strip()]
    out = lines[2].strip()
    print(solve_lfsr_filter(M1, M2, out))
