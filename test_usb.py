#!/usr/bin/env python3
"""Samsung SCX-4623fw USB 真机验证（只读查询，无副作用）

用法（二选一）：
  sudo -u fn-scx4623 python3 /home/HH0113/fn-scx4623/test_usb.py
  sudo python3 /home/HH0113/fn-scx4623/test_usb.py

只发 3 类 vendor IN 查询（EPM 轮询用的同款命令），不做任何写操作。
"""
import sys
import os
import json
import struct

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "app", "server"))
import usb_supply as U


def main():
    print("=" * 64)
    print("[1] 设备发现")
    dev = U.find_device()
    print("    path =", dev)
    if not dev:
        print("    ❌ 未找到 04e8:3434")
        return 1

    print("\n[2] 查询当前状态（C1 02, wValue=0, wLen=8）")
    try:
        st = U.get_status_bytes(dev)
    except OSError as e:
        print(f"    ❌ {type(e).__name__}: {e}")
        print("    （多半是权限：需要 lp 组或 root）")
        return 2
    print("    status =", st.hex(" "))

    print("\n[3] 拉状态字典 XML（C1 0D, 19 片）")
    xml = U.get_status_xml(dev, cache_path="/tmp/samsung_state_dict.xml")
    print(f"    {len(xml)} 字节" + ("（已缓存 /tmp/samsung_state_dict.xml）" if xml else ""))
    sigs = U.parse_state_sigs(xml) if xml else {}
    print(f"    解析出 {len(sigs)} 个状态签名")

    print("\n[4] 状态匹配")
    sigs = sigs or U.FALLBACK_SIGS
    states = U.match_state(st, sigs)
    print("    命中:", states)

    print("\n[5] 碳粉判定")
    toner = None
    for s in states:
        if s in U.TONER_STATES:
            toner = U.TONER_STATES[s]
            print(f"    ⚠ {s} → {toner}")
            break
    if not toner:
        print("    ✅ 无耗材告警（碳粉状态正常）")

    print("\n[6] 固件版本（C1 56, wLen=64）")
    try:
        print("    ", U.get_firmware(dev))
    except OSError as e:
        print("    查询失败:", e)

    print("\n[7] 汇总 query() 返回")
    pkgvar = "/tmp/fnprint_pkgvar"
    os.makedirs(pkgvar, exist_ok=True)
    print(json.dumps(U.query(pkgvar), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
