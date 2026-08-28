#!/usr/bin/env python3
"""陇剑杯2024 SmallSword 前置: redis.service 路径 md5 复现校验。

原题: 排查 redis 自启动服务, 锁定路径 /lib/systemd/system/redis.service, 提交其 md5。
可本地确定性复现, 故作为该 forensic 题的 verified_solver。
"""
import hashlib

PATH = "/lib/systemd/system/redis.service"
EXPECTED = "b2c5af8ce08753894540331e5a947d35"


def main():
    h = hashlib.md5(PATH.encode("utf-8")).hexdigest()
    if h == EXPECTED:
        print(f"VERIFIED redis.service md5 = {h}")
        return 0
    print(f"MISMATCH got={h} expected={EXPECTED}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
