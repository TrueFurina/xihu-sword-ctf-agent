#!/usr/bin/env python3
"""生成 某省赛(路由器设备流量分析) forensic 真题 —— 取自本地金矿
`10.CTF Misc/CTF隐写题目/赛题与题解.pdf`(leadlife 文档, 实为该省赛流量分析题集)。

文档给出 capture.pcapng 的 13 道任务题面与部分解题; 仅取 writeup 中**明确写出答案值**的 5 道,
其余需原 pcap 计数的(404报文数/ping请求数/重定向数/ssh算法等)不谎报、不入库。

约定同前: JSON flag=sha256(明文), 明文存 gitignored _attachments。
"""
import hashlib
import json
import os

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "questions_real"))

PROBLEMS = [
    dict(
        pid="real_misc_sheng2022_traffic_telnet_pwd", cat="misc",
        title="某省赛 路由器流量分析 题1 telnet密码",
        description="Wireshark 分析 capture.pcapng, 找出 telnet(路由器) 账号 admin / 密码; "
                    "writeup 明确给出密码 Cisc0。flag{密码}。",
        flag="Cisc0", flag_pattern=r"^[A-Za-z0-9]+$",
        difficulty="EASY", source="CTF隐写题目/赛题与题解.pdf(leadlife 某省赛流量分析)",
    ),
    dict(
        pid="real_misc_sheng2022_traffic_enable_pwd", cat="misc",
        title="某省赛 路由器流量分析 题2 enable特权密码",
        description="同上 pcap, telnet 设备 enable 特权密码; writeup 明确给出 cisco123。flag{密码}。",
        flag="cisco123", flag_pattern=r"^[A-Za-z0-9]+$",
        difficulty="EASY", source="CTF隐写题目/赛题与题解.pdf(leadlife 某省赛流量分析)",
    ),
    dict(
        pid="real_misc_sheng2022_traffic_bruteforce_count", cat="misc",
        title="某省赛 路由器流量分析 题3 爆破次数",
        description="统计 192.168.181.141 对 telnet 路由器的密码爆破次数; writeup 明确给出 145。flag{次数}。",
        flag="145", flag_pattern=r"^\d+$",
        difficulty="MEDIUM", source="CTF隐写题目/赛题与题解.pdf(leadlife 某省赛流量分析)",
    ),
    dict(
        pid="real_misc_sheng2022_traffic_ftp_dataconn_count", cat="misc",
        title="某省赛 路由器流量分析 题5 FTP数据连接次数",
        description="ftp 传输结束后建立的数据连接次数; writeup 明确给出 1。flag{次数}。",
        flag="1", flag_pattern=r"^\d+$",
        difficulty="EASY", source="CTF隐写题目/赛题与题解.pdf(leadlife 某省赛流量分析)",
    ),
    dict(
        pid="real_misc_sheng2022_traffic_ftp_port", cat="misc",
        title="某省赛 路由器流量分析 题6 首次数据连接端口",
        description="ftp 登录后第一次使用数据连接的端口号; writeup 明确给出 80。flag{端口}。",
        flag="80", flag_pattern=r"^\d+$",
        difficulty="EASY", source="CTF隐写题目/赛题与题解.pdf(leadlife 某省赛流量分析)",
    ),
]


def sha256hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main():
    for p in PROBLEMS:
        pid, cat, pt = p["pid"], p["cat"], p["flag"]
        h = sha256hex(pt)
        att_dir = os.path.join(BASE, "_attachments", cat, pid)
        os.makedirs(att_dir, exist_ok=True)
        with open(os.path.join(att_dir, "flag.txt"), "w", encoding="utf-8") as f:
            f.write(pt + "\n")
        obj = {
            "id": pid, "provenance": "real_past_ctf", "category": cat,
            "title": p["title"], "description": p["description"],
            "flag": h, "flag_pattern": p["flag_pattern"],
            "attachments": [f"data/questions_real/_attachments/{cat}/{pid}/flag.txt"],
            "difficulty": p["difficulty"], "flag_sha256": h,
            "verified_solver": False, "source": p["source"],
        }
        out = os.path.join(BASE, cat, pid + ".json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2); f.write("\n")
        print(f"WROTE {out} plaintext={pt} sha256={h}")


if __name__ == "__main__":
    main()
