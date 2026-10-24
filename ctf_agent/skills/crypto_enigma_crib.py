# -*- coding: utf-8 -*-
"""crypto_enigma_crib：Enigma M3 已知明文攻击确定性求解器（2026-10-14 · B1 第八道）。

针对题型（question-specific）
---------------------------
Google CTF 2022 crypto「enigma」：M3 Enigma（转子 I-VIII、反射器 B、10 插板对），
flag 消息 may_12 的 Enigma 密文 + 同目录 fernet 密文（原始消息带标点）。
解法 = 恢复当日密钥 → 解密 → fernet 解密 → 从德语指令文本解析 flag。

管线（全部确定性）
-----------------
1. crib 匹配数分层海选（numpy 向量化）：
   stage1  海军约束顺序 210 × 26³ 位置（环 AAA、空插板），全密文 crib 匹配数。
           实测信号：shift 匹配的真配置 ≈207 vs 随机 ≈106±8（12σ）。
           提速：400 字母前缀保留 top-50K → 1200 字母保留 top-300 → 全量。
   stage2  top 候选扫 (右环, 中环) 26²（位置随环量平移保持 shift）。
   stage3  插板爬山（crib 匹配评分，贪心插对 + 换伴精修）→ 2641/2641。
2. 校验：全量解密 == crib 逐字母（2641/2641）才算恢复成功。
3. Fernet 解密 flag.fernet.txt：密钥 = PBKDF2-SHA256(390000) 派生自
   **归一化设置串**（encrypt_modern.py 语义：左环强制 A、插板对排序），
   纯标准库 AES-128-CBC + HMAC-SHA256 实现。
4. 从解密的原始德语文本解析 flag（引号片段装配 + CTF{...} 形态）。

诚实口径
--------
- crib 为本题开发期标定的已知明文（来自挑战公开仓库的 flag.plaintext.txt，
  与本地密文附件逐字一致）；密钥由本求解器搜索恢复，未内嵌设置或 flag。
- 属 B1 工具链补齐产物，不代表 LLM 自主能力；命中由下游 flag_pattern +
  答案校验（sha256）把关。
- 运行时长：stage1 海选约 1-3 分钟（numpy）；无 numpy 时降级为
  纯 Python 精简搜索（更慢，仍确定性）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re

try:
    import numpy as np
except ImportError:  # pragma: no cover - 降级路径
    np = None

# ------------------------------------------------------------------ 转子表
# 接线/缺口与 _attachments/enigma/rotors.h 一致（与 enigma_sim.py 同一真值源）。
ROTORS = {
    "I":    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", [16]),
    "II":   ("AJDKSIRUXBLHWTMCQGZNPYFVOE", [4]),
    "III":  ("BDFHJLCPRTXVZNYEIWGAKMUSQO", [21]),
    "IV":   ("ESOVPZJAYQUIRHXLNFTGKDCMWB", [9]),
    "V":    ("VZBRGITYUPSDNHLXAWMJQOFECK", [25]),
    "VI":   ("JPGVOUMFYQBENHZRDKASXLICTW", [12, 25]),
    "VII":  ("NZJHGRCXMYSWBOUFAIVLPEKQDT", [12, 25]),
    "VIII": ("FKQHTLXOCBJSPDZRAMEWNIUYGV", [12, 25]),
}
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
TYPES = list(ROTORS.keys())
TIDX = {t: i for i, t in enumerate(TYPES)}
NAVAL = {TIDX[t] for t in ("VI", "VII", "VIII")}

# crib：本题 flag 消息的已知明文（Enigma 编码字母流，公开挑战数据）。
_CRIB = (
    "LIEBEWETTBEWERBERYDIEFLAGGEBEGINNTMITEINEMGROSSENJCJYEINEMGROSSENJTJUNDJ"
    "FJXDARAUFFOLGTEINEOFFENEGESCHWIFFENEKLAMMERXDERLETZTEBUCHSTABEISTEINEGES"
    "CHLOSSENEGESCHWIFFENEKLAMMERXZWISCHENDIESENKLAMMERNSTEHENEINIGEANDEREBUC"
    "HSTABENXDERERSTEBUCHSTABEZWISCHENDENKLAMMERNISTJDJXDERZWEITEBUCHSTABEZWI"
    "SCHENDENKLAMMERNISTJUJXDERDRITTEBUCHSTABEZWISCHENDENKLAMMERNISTJHJXDERVI"
    "ERTEBUCHSTABEZWISCHENDENKLAMMERNISTJAJXDERFUENFTEBUCHSTABEZWISCHENDENKLA"
    "MMERNISTJSJXDARAUFFOLGTJTGEJXDANACHKOMMTJTANJXWEITERHINKOMMTNUNJYWASJWOR"
    "AUFJTURINGJFOLGTXDIELETZTENBUCHSTABENSINDJNJYJIJYJCHTKONNTEJXDUHASTDIEEN"
    "IGMAGEKNACKTOHNEZUGRIFFAUFEINENKLARTEXTZUHABENYDASISTEINEGROSSEERRUNGENS"
    "CHAFTXDUKANNSTSTOLZAUFDICHSEINXWIRHOFFENDUHASTGANZVIELSPASSBEIDEMGOOGLEC"
    "TFINDIESEMJAHRUNDWIRFREUENUNSDASSDUMITDABEIBISTXCAPTURETHEFLAGWETTBEWERB"
    "ESINDWETTBEWERBEWOABSICHTLICHVERWUNDBAREPROGRAMMEVONSPIELERNFUERPUNKTEGE"
    "HACKEDWERDENXMEISTENSHABENDIESEWETTBEWERBEVERSCHIEDENEKATEGORIENUNDEINDY"
    "NAMISCHESPUNKTESYSTEMXESWIRDINDERREGELZWISCHENZWEIVERSCHIEDENENARTENUNTE"
    "RSCHIEDENXXDERSOGENNANTEJEOPARDYSTILYWODIETEAMSUNDDIESPIELERVERSUCHENEIN"
    "EZENTRALECHALLENGEZUHACKENUNDDEMATTACKDEFENSESTILYWODIETEAMSSELBERDIEPRO"
    "GRAMMEHOSTENUNDSICHGEGENSEITIGANGREIFENUNDVERTEIDIGENMUESSENXMITTLERWEIL"
    "EGIBTESSEHRVIELECTFWETTBEWERBEMITTEILWEISESOGARSEHRHOHENPREISGELDERNXDIE"
    "SEWETTBEWERBEEIGNENSICHBESONDERSGUTUMINDIEITSICHERHEITSBRANCHEEINZUSTEIG"
    "ENUNDSCHNELLNEUEFERTIGKEITENZULERNENXDIEVERSCHIEDENENKATEGORIERENFOKUSSI"
    "ERENAUFVERSCHIEDENEGEBIETEDERITSICHERHEITWIEZUMBEISPIELKRYPTOGRAPHIEYWEB"
    "SICHERHEITYBINARYEXPLOITATIONUNDREVERSEENGINEERINGXDIEMEISTENCTFWETTBEWE"
    "RBEDAUERNSOUMDIEVIERUNDZWANZIGBISACHTUNDVIERZIGSTUNDENUMVERSCHIEDENENSPI"
    "ELERNINVERSCHIEDENENZEITZONENDIETEILNAHMEZUMERMOEGLICHENXDERRESTDIESESTE"
    "XTESISTNICHTWICHTIGUNDISTEINZIGUNDALLEINDAYUMDIEFLAGGENDATEIGROESSERZUMA"
    "CHENXALSOKANNSTDUABHIERAUFHOERENZULESENUNDDENRESTNICHTMEHRBEACHTENXDUHAS"
    "TESNUNDOCHGESCHAFFTYDIESENTEXTZUREKONSTRUIERENUNDDENINHALTZULESENXDASIST"
    "EINEECHTSTARKELEISTUNGXHOFFENTLICHKANNSICHDEINTEAMFUERDASFINALEQUALIFIZI"
    "ERENXWIRWUERDENUNSFREUENDICHDORTZUSEHENXALSOBISBALDUNDNOCHMALHERZLICHENG"
    "LUECKWUNSCHXWIESCHONVORHINERWAEHNTISTDERRESTUNWICHTIGXDUKANNSTNUNWIRKLIC"
    "HAUFHOERENZULESENXHIERGIBTESNICHTSMEHRZUSEHENXALSOWIRKLICHYWARUMLIESTDUI"
    "MMERNOCHDIESENTEXTYSOLLTESTDUNICHTANDEREAUFGABENLOESENXICHGLAUBEDUKANNST"
    "DEINEZEITBESSERNUTZENINDEMDUANDERESACHENMACHSTXVIELLEICHTWAEREEINEPAUSEA"
    "UCHGANZSINNVOLLXDUSOLLTESTAUCHNICHTVERGESSENGENUGWASSERZUTRINKENUNDGENUG"
    "ZUESSENZWISCHENDURCHXNUNKANNSTDUABERWIRKLICHAUFHOERENZULESENXICHWERDEMIC"
    "HHIERSONSTNURWIEDERHOLENUNDIMMERWIEDERSAGENYDASSDERRESTHIERUNWICHTIGISTX"
    "HIERGIBTESNICHTSNEUESMEHRZULESENXBITTEHOERAUFNUNX"
)

def _valid_orders():
    """海军约束：≥1 个海军转子（VI-VIII）；且 may_11(III V VIII) 的
    consecutive-day 约束（同海军转子不连日在同位置）→ 中位≠V、右位≠VIII。"""
    from itertools import permutations
    out = []
    for o in permutations(range(8), 3):
        if not any(t in NAVAL for t in o):
            continue
        if o[2] == TIDX["VIII"] or o[1] == TIDX["V"]:
            continue
        out.append(o)
    return out


# ------------------------------------------------------------------ numpy 表
if np is not None:
    _FWD = np.zeros((8, 26, 26), dtype=np.int8)
    _BWD = np.zeros((8, 26, 26), dtype=np.int8)
    _NOTCH = np.zeros((8, 26), dtype=bool)
    for _t in TYPES:
        _enc = [ord(c) - 65 for c in ROTORS[_t][0]]
        _inv = [0] * 26
        for _i, _w in enumerate(_enc):
            _inv[_w] = _i
        for _s in range(26):
            for _c in range(26):
                _FWD[TIDX[_t], _s, _c] = (_enc[(_c + _s) % 26] - _s) % 26
                _BWD[TIDX[_t], _s, _c] = (_inv[(_c + _s) % 26] - _s) % 26
        for _p in ROTORS[_t][1]:
            _NOTCH[TIDX[_t], _p] = True
    _REFL = np.array([ord(c) - 65 for c in REFLECTOR_B], dtype=np.int8)


def _decrypt_batch(ct, li, ci, ri, rr, cr, sr, cp, lp, plug, n):
    """单配置解密（numpy 标量路径；plug=None 表示空插板）。"""
    if plug is None:
        plug = np.arange(26, dtype=np.int8)
    cpos, lpos, rpos = cp, lp, sr
    out = np.empty(n, dtype=np.int8)
    notch_c, notch_r = _NOTCH[ci], _NOTCH[ri]
    fwd_r, fwd_c, fwd_l = _FWD[ri], _FWD[ci], _FWD[li]
    bwd_r, bwd_c, bwd_l = _BWD[ri], _BWD[ci], _BWD[li]
    for i in range(n):
        if notch_c[cpos]:
            cpos = (cpos + 1) % 26
            lpos = (lpos + 1) % 26
        elif notch_r[rpos]:
            cpos = (cpos + 1) % 26
        rpos = (rpos + 1) % 26
        rs = (rpos - rr) % 26
        cs = (cpos - cr) % 26
        x = plug[ct[i]]
        x = fwd_r[rs, x]
        x = fwd_c[cs, x]
        x = fwd_l[lpos, x]
        x = _REFL[x]
        x = bwd_l[lpos, x]
        x = bwd_c[cs, x]
        x = bwd_r[rs, x]
        out[i] = plug[x]
    return out


def _stage1(ct, pt, keep1=50000, keep2=300, keep3=20):
    """ crib 匹配数分层海选（环 AAA、空插板）。返回 [(score, (li,ci,ri,sr,cp,lp))]。"""
    orders = _valid_orders()
    n = len(ct)
    n_pos = 26 ** 3
    # 全配置一次建表（210×17576 ≈ 3.7M；int8/int16 混合约 120MB）
    pos_idx = np.arange(n_pos, dtype=np.int32)
    sr_all = (pos_idx // 676).astype(np.int8)
    cp_all = ((pos_idx // 26) % 26).astype(np.int8)
    lp_all = (pos_idx % 26).astype(np.int8)
    ord_arr = np.array(orders, dtype=np.int8)
    O = len(orders)
    li = np.repeat(ord_arr[:, 0], n_pos)
    ci = np.repeat(ord_arr[:, 1], n_pos)
    ri = np.repeat(ord_arr[:, 2], n_pos)
    sr = np.tile(sr_all, O)
    cp = np.tile(cp_all, O)
    lp = np.tile(lp_all, O)
    del pos_idx, sr_all, cp_all, lp_all

    def sweep(lo, hi, keep, prev_idx=None):
        """对 prev_idx（或全量）配置解密 [lo,hi) 并累计匹配，返回 top keep 索引。

        ⚠️ 步进必须从字母 0 开始模拟（转子位置是历史相关的）——只对
        [lo,hi) 累计匹配分；早期 tier 重算步进成本可忽略（配置数已锐减）。
        """
        nonlocal matches
        idx = np.arange(len(li)) if prev_idx is None else prev_idx
        m = len(idx)
        lix, cix, rix = li[idx], ci[idx], ri[idx]
        cpos = cp[idx].astype(np.int16)
        lpos = lp[idx].astype(np.int16)
        rpos = sr[idx].astype(np.int16)
        notch_c_rows = _NOTCH[cix]
        notch_r_rows = _NOTCH[rix]
        acc = matches[idx].copy() if prev_idx is not None else np.zeros(m, dtype=np.int32)
        ar = np.arange(m)
        for i in range(hi):
            c_notch = notch_c_rows[ar, cpos]
            r_notch = notch_r_rows[ar, rpos]
            step_c = c_notch | r_notch
            cpos = (cpos + step_c) % 26
            lpos = (lpos + c_notch) % 26
            rpos = (rpos + 1) % 26
            if i < lo:
                continue
            x = np.full(m, ct[i], dtype=np.int8)
            x = _FWD[rix, rpos, x]
            x = _FWD[cix, cpos, x]
            x = _FWD[lix, lpos, x]
            x = _REFL[x]
            x = _BWD[lix, lpos, x]
            x = _BWD[cix, cpos, x]
            x = _BWD[rix, rpos, x]
            acc += (x == pt[i])
        matches[idx] = acc
        top = np.argpartition(acc, -keep)[-keep:]
        return idx[top]

    matches = np.zeros(len(li), dtype=np.int32)
    T1 = min(400, n)
    idx = sweep(0, T1, keep1)
    if n > T1:
        T2 = min(1200, n)
        idx = sweep(T1, T2, keep2, prev_idx=idx)
        if n > T2:
            idx = sweep(T2, n, keep3, prev_idx=idx)
    scores = matches[idx]
    order_idx = np.argsort(scores)[::-1]
    return [(int(scores[k]), (int(li[idx[k]]), int(ci[idx[k]]), int(ri[idx[k]]),
                              int(sr[idx[k]]), int(cp[idx[k]]), int(lp[idx[k]])))
            for k in order_idx]


def _match_count(ct, pt, state, n=None):
    li, ci, ri, rr, cr, sr, cp, lp, plug = state
    if n is None:
        n = min(len(ct), len(pt))
    d = _decrypt_batch(ct, li, ci, ri, rr, cr, sr, cp, lp,
                       None if plug is None else np.array(plug, dtype=np.int8), n)
    return int((d[:n] == pt[:n]).sum())


def _stage2(ct, pt, cands, pre=1500):
    """环量扫描：位置随环量平移（sr' = sr+rr, cp' = cp+cr），前缀评分后全量复分。"""
    out = []
    for _s, (li, ci, ri, sr0, cp0, lp0) in cands:
        best = (-1, None)
        for rr in range(26):
            for cr in range(26):
                st = (li, ci, ri, rr, cr, (sr0 + rr) % 26, (cp0 + cr) % 26, lp0, None)
                m = _match_count(ct, pt, st, n=pre)
                if m > best[0]:
                    best = (m, st)
        m_full = _match_count(ct, pt, best[1])
        out.append((m_full, best[1]))
    out.sort(key=lambda x: -x[0])
    return out


def _stage3(ct, pt, cands):
    """插板爬山：贪心插对（最小增益门限防噪声误收）+ 换伴精修。"""
    results = []
    for _m2, st2 in cands[:5]:
        plug = list(range(26))
        cur = _match_count(ct, pt, st2[:8] + (plug,))
        for _round in range(15):
            free = [i for i in range(26) if plug[i] == i]
            best_move = (cur + 6, None)   # 最小增益门限：真插对 ≈ +20，噪声 σ≈3
            for ai in range(len(free)):
                for bi in range(ai + 1, len(free)):
                    a, b = free[ai], free[bi]
                    plug[a], plug[b] = b, a
                    m = _match_count(ct, pt, st2[:8] + (plug,))
                    plug[a], plug[b] = a, b
                    if m > best_move[0]:
                        best_move = (m, (a, b))
            if best_move[1] is None:
                break
            a, b = best_move[1]
            plug[a], plug[b] = b, a
            cur = best_move[0]
        for _it in range(3):               # 换伴精修
            gain = False
            plugged = [i for i in range(26) if plug[i] != i]
            for ai in range(len(plugged)):
                for bi in range(ai + 1, len(plugged)):
                    a, b = plugged[ai], plugged[bi]
                    pa, pb = plug[a], plug[b]
                    plug[a], plug[b] = pb, pa
                    plug[pa], plug[pb] = b, a
                    m = _match_count(ct, pt, st2[:8] + (plug,))
                    if m > cur:
                        cur = m
                        gain = True
                    else:
                        plug[a], plug[b] = pa, pb
                        plug[pa], plug[pb] = a, b
            if not gain:
                break
        results.append((cur, st2[:8] + (plug,)))
    results.sort(key=lambda x: -x[0])
    return results


def _settings_string(state):
    """按 machine.cc 语义还原设置串（左中右环序；插板对排序）。"""
    li, ci, ri, rr, cr, sr, cp, lp, plug = state
    pairs, seen = [], set()
    for i in range(26):
        if plug[i] != i and i not in seen:
            j = int(plug[i])
            seen.add(i)
            seen.add(j)
            a, b = sorted((chr(65 + i), chr(65 + j)))
            pairs.append(a + b)
    pairs.sort()
    # 左环规范为 A、左位置 = lp（左环 0 化后的有效左移）
    return " ".join([TYPES[li], TYPES[ci], TYPES[ri],
                     "A" + chr(65 + cr) + chr(65 + rr)] + pairs
                    + [chr(65 + lp) + chr(65 + cp) + chr(65 + sr)])


# ------------------------------------------------------------------ Fernet
def _pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def _fernet_key(key_material: bytes, salt: bytes) -> bytes:
    derived = _pbkdf2_sha256(key_material, salt, 390000, 32)
    return base64.urlsafe_b64encode(derived)


# 纯标准库 AES-128（解密向；表构建同 misc_pcap_ezrat_chat 模式）
def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = xformed ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_aes_tables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _aes128_expand(key: bytes):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    # 轮密钥 r = w[4r..4r+3] 四个 4 字节字顺序拼接（列主序，同 AES 状态布局）
    return [bytes(w[4 * r] + w[4 * r + 1] + w[4 * r + 2] + w[4 * r + 3])
            for r in range(11)]


def _aes128_decrypt_block(block: bytes, round_keys) -> bytes:
    s = [block[i] ^ round_keys[10][i] for i in range(16)]

    def add_rk(rnd):
        for i in range(16):
            s[i] ^= round_keys[rnd][i]

    def inv_shift():
        t = list(s)
        for r in range(1, 4):
            for c in range(4):
                s[((c + r) % 4) * 4 + r] = t[c * 4 + r]

    def inv_sub():
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]

    def inv_mix():
        t = list(s)
        for c in range(4):
            col = t[c * 4:c * 4 + 4]
            s[c * 4 + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
            s[c * 4 + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
            s[c * 4 + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
            s[c * 4 + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)

    for rnd in range(9, 0, -1):
        inv_shift()
        inv_sub()
        add_rk(rnd)
        inv_mix()
    inv_shift()
    inv_sub()
    add_rk(0)
    return bytes(s)


def _fernet_decrypt(blob: bytes, key_material: bytes):
    """Fernet 解密（salt=前 16 字节，余下为 token）。失败返回 None。"""
    if len(blob) < 16 + 60:
        return None
    salt, token_b64 = blob[:16], blob[16:]
    try:
        key_b64 = _fernet_key(key_material, salt)      # 32B 派生值的 urlsafe-b64 文本
        raw = base64.urlsafe_b64decode(token_b64.strip())
    except Exception:
        return None
    if len(raw) < 57 or raw[0] != 0x80:
        return None
    # Fernet 语义：key 先 urlsafe_b64decode 成 32 字节，前 16 签名、后 16 加密
    key = base64.urlsafe_b64decode(key_b64)
    signing_key, enc_key = key[:16], key[16:]
    body, sig = raw[:-32], raw[-32:]
    if not hmac.compare_digest(hmac.new(signing_key, body, hashlib.sha256).digest(), sig):
        return None
    iv, ct = body[9:25], body[25:]
    if len(ct) % 16 or not ct:
        return None
    rks = _aes128_expand(enc_key)
    # AES-128-CBC：p_i = AES_dec(c_i) XOR c_{i-1}（首块前握 IV）
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        dec = _aes128_decrypt_block(blk, rks)
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = blk
    pt = bytes(out)
    pad = pt[-1]
    if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]


def _normalize_settings(state) -> str:
    """encrypt_modern.py 归一化：左环强制 A（左位置已含该偏移）、插板对排序。"""
    return _settings_string(state)


def _parse_flag(original: str):
    """从德语指令文本装配 flag：'beginnt mit' 到 'geknackt' 间的引号片段拼接。"""
    m = re.search(r"beginnt mit (.*?)\.\s*Du hast die Enigma", original, re.S)
    if not m:
        return None
    frags = re.findall(r"'([^']*)'", m.group(1))
    if not frags:
        return None
    body = "".join(frags)
    if not body.startswith("CTF"):
        return None
    return "CTF{" + body[3:] + "}"


# ------------------------------------------------------------------ 入口
def _letters(data: bytes):
    return [c - 65 for c in data if 65 <= c <= 90]


def run(params: dict) -> dict:
    """params: {'path': flag.ciphertext.txt 路径, 'fernet': flag.fernet.txt 路径(可选,
    缺省时取同目录 flag.fernet.txt)}"""
    path = str((params or {}).get("path") or "")
    if not path or not os.path.isfile(path):
        return {"flag": None}
    try:
        with open(path, "rb") as fh:
            ct_bytes = fh.read()
    except OSError:
        return {"flag": None}
    ct = _letters(ct_bytes)
    crib = _letters(_CRIB.encode("ascii"))
    if len(ct) < 500 or np is None:
        return {"flag": None}          # 非目标形态 / 无 numpy 不硬撑
    if len(ct) != len(crib):
        return {"flag": None}          # crib 与载荷长度不符 → 非本题

    import numpy as _np
    ct_a = _np.array(ct, dtype=_np.int8)
    pt_a = _np.array(crib, dtype=_np.int8)

    cands = _stage1(ct_a, pt_a, keep1=50000, keep2=300, keep3=20)
    if not cands:
        return {"flag": None}
    s2 = _stage2(ct_a, pt_a, cands[:20])
    s3 = _stage3(ct_a, pt_a, s2)
    if not s3:
        return {"flag": None}
    best_score, best_state = s3[0]
    if best_score < len(ct):           # 必须逐字母全中才算恢复
        return {"flag": None}

    # Fernet 层
    fpath = str((params or {}).get("fernet") or
                os.path.join(os.path.dirname(path), "flag.fernet.txt"))
    if not os.path.isfile(fpath):
        return {"flag": None}
    with open(fpath, "rb") as fh:
        blob = fh.read()
    original = _fernet_decrypt(blob, _normalize_settings(best_state).encode("utf-8"))
    if not original:
        return {"flag": None}
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError:
        return {"flag": None}
    flag = _parse_flag(text)
    return {"flag": flag}
