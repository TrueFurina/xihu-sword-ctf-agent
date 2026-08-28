#!/usr/bin/env python3
"""生成 陇剑杯2024(第二届初赛) + 陇剑杯2025决赛 的 forensic/应急响应真题 JSON + 明文 flag 附件。

约定(与被删真题库重建一致):
- JSON 的 flag / flag_sha256 字段 = sha256(明文 flag)
- 明文 flag 存 gitignored 的 data/questions_real/_attachments/{cat}/{pid}/flag.txt
- verified_solver=False(这些 forensic 答案为流量/日志推导, 无原 pcap 无法自动复现)
- 仅 longjian2024_ssw_redis 可本地复现校验(md5 路径), 故写 solver 并标记 verified_solver=True

纯增量语料, 不进 KPI 分母 manifest(防指标膨胀)。
"""
import hashlib
import json
import os

BASE = os.path.join(os.path.dirname(__file__), "..", "data", "questions_real")
BASE = os.path.abspath(BASE)

PROBLEMS = [
    # ---------------- 第二届陇剑杯2024 初赛 (应急响应/数据安全) ----------------
    dict(
        pid="real_misc_longjian2024_ssw_redis", cat="misc",
        title="陇剑杯2024 数据分析-SSW redis.service 路径md5",
        description="排查 redis 自启动服务, 锁定路径 /lib/systemd/system/redis.service, "
                    "提交其 md5(echo -n '/lib/systemd/system/redis.service' | md5sum)。"
                    "可本地实跑校验。",
        flag="b2c5af8ce08753894540331e5a947d35",
        flag_pattern=r"^[0-9a-f]{32}$",
        difficulty="EASY", source="第二届陇剑杯2024 初赛WP(博客)",
        verified_solver=True, solver="scripts/_solve_longjian2024_redis.py",
    ),
    dict(
        pid="real_misc_longjian2024_smallsword1", cat="misc",
        title="陇剑杯2024 SmallSword_1 蚁剑连接密码",
        description="流量分析 SQL 联合注入写入 webshell, 追踪 HTTP 流在 $_POST 中找到蚁剑连接密码。",
        flag="6ea280898e404bfabd0ebb702327b18f",
        flag_pattern=r"^[0-9a-f]{32}$",
        difficulty="MEDIUM", source="第二届陇剑杯2024 初赛WP(博客)",
        verified_solver=False,
    ),
    dict(
        pid="real_misc_longjian2024_smallsword2", cat="misc",
        title="陇剑杯2024 SmallSword_2 攻击者留存值",
        description="分析蚁剑流量, 找到向 hacker.txt 写入的 base64 解码值(攻击者留存的值)。",
        flag="ad6269b7-3ce2-4ae8-b97f-f259515e7a91",
        flag_pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        difficulty="MEDIUM", source="第二届陇剑杯2024 初赛WP(博客)",
        verified_solver=False,
    ),
    dict(
        pid="real_misc_longjian2024_smallsword3", cat="misc",
        title="陇剑杯2024 SmallSword_3 攻击者下载的flag",
        description="导出 huorong.exe 流量, 去除蚁剑识别头 ->| 保存为 exe, pyinstaller 打包, "
                    "运行后上一层目录拿到图片, 修复宽高得 flag。",
        flag="flag3{8f0dffac-5801-44a9-bd49-e66192ce4f57}",
        flag_pattern=r"flag3\{[^}]+\}",
        difficulty="HARD", source="第二届陇剑杯2024 初赛WP(博客)",
        verified_solver=False,
    ),
    dict(
        pid="real_misc_longjian2024_telnet", cat="misc",
        title="陇剑杯2024 数据分析-telnet 被入侵主机口令",
        description="入侵协议为 telnet, 追踪流得被入侵主机(192.168.246.28)的口令。",
        flag="youcannevergetthis",
        flag_pattern=r"^[a-z]+$",
        difficulty="EASY", source="第二届陇剑杯2024 初赛WP(博客)",
        verified_solver=False,
    ),
    # ---------------- 第四届陇剑杯2025 决赛 ----------------
    dict(
        pid="real_misc_longjian2025_data_security1", cat="misc",
        title="陇剑杯2025 决赛 数据安全1 身份证md5",
        description="流量大量 HTTP 对象泄露身份证号, 按数据被窃取时间排序后合并计算 md5 提交。",
        flag="flag{22f0478916408f8026b4eb61204ab930}",
        flag_pattern=r"flag\{[0-9a-f]{32}\}",
        difficulty="MEDIUM", source="第四届陇剑杯2025 决赛WP(博客)",
        verified_solver=False,
    ),
    dict(
        pid="real_web_longjian2025_which_sql", cat="web",
        title="陇剑杯2025 决赛 which_sql SQL盲注flag",
        description="数据库被 SQL 盲注, 日志中每字段某字符以 != 结束, 用 cyberchef 过滤 ctf_flags 表 "
                    "第二列得真 flag(ctfplus{} 格式; 另有等价变体 flag{wwwWow_u_2re_sql_master})。",
        flag="ctfplus{Wow_u_2re_sql_master}",
        flag_pattern=r"ctfplus\{[^}]+\}",
        difficulty="MEDIUM", source="第四届陇剑杯2025 决赛WP(博客)",
        verified_solver=False,
    ),
    dict(
        pid="real_misc_longjian2025_app_part2", cat="misc",
        title="陇剑杯2025 决赛 app_part2 webshell流量秘密",
        description="webshell 流量(php 一句话 XOR 加密), 解码得工作目录/输出内容/黑客找到的秘密。",
        flag="flag{app_part2!@#_The_Last_Part_U_Fin3}",
        flag_pattern=r"flag\{[^}]+\}",
        difficulty="MEDIUM", source="第四届陇剑杯2025 决赛WP(博客)",
        verified_solver=False,
    ),
    dict(
        pid="real_misc_longjian2025_siem", cat="misc",
        title="陇剑杯2025 决赛 siem-加密 综合取证flag",
        description="wazuh 日志分析 app 被爆破, 提取攻击者IP/会话数/后门用户/url/事件ID/工具/删除文件名, "
                    "md5 组合提交: 192.168.41.143-13-hacker-http://192.168.41.136/.back.php?pass=id-"
                    "1734511987.34749419-mimikatz-ossec.conf。",
        flag="flag{3bfc26f5d9f932ccf73f356019585edf}",
        flag_pattern=r"flag\{[0-9a-f]{32}\}",
        difficulty="HARD", source="第四届陇剑杯2025 决赛WP(博客)",
        verified_solver=False,
    ),
]


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def main():
    created = []
    for p in PROBLEMS:
        pid = p["pid"]; cat = p["cat"]; plaintext = p["flag"]
        h = sha256hex(plaintext)
        # 明文附件
        att_dir = os.path.join(BASE, "_attachments", cat, pid)
        os.makedirs(att_dir, exist_ok=True)
        with open(os.path.join(att_dir, "flag.txt"), "w", encoding="utf-8") as f:
            f.write(plaintext + "\n")
        # JSON
        obj = {
            "id": pid,
            "provenance": "real_past_ctf",
            "category": cat,
            "title": p["title"],
            "description": p["description"],
            "flag": h,
            "flag_pattern": p["flag_pattern"],
            "attachments": [
                f"data/questions_real/_attachments/{cat}/{pid}/flag.txt"
            ],
            "difficulty": p["difficulty"],
            "flag_sha256": h,
            "verified_solver": p["verified_solver"],
            "source": p["source"],
        }
        if p.get("solver"):
            obj["solver"] = p["solver"]
        out = os.path.join(BASE, cat, pid + ".json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
        created.append((out, plaintext, h))
    for out, pt, h in created:
        print(f"WROTE {out}\n   plaintext={pt}\n   sha256={h}")


if __name__ == "__main__":
    main()
