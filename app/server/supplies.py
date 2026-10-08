#!/usr/bin/env python3
"""fn-scx4623 耗材查询：USB 厂商协议（首选）+ SNMP + CUPS 状态位 + 手动记录兜底。

数据源优先级：
  0. USB —— Samsung 专有 vendor 协议（逆向自 EPM 抓包），真实设备状态 + 剩余百分比
  1. SNMP —— 打印机接了网络时的真实余量（标准 Printer MIB，Samsung 支持）
  2. CUPS printer-state-reasons —— toner-low / toner-empty 等布尔状态
  3. 手动记录 —— 用户登记换粉日期与页数，按页估算
"""

import json
import os
import re
import socket
import time

# Printer MIB (RFC 3805) —— prtMarker 表，索引 1 通常是成像装置/墨粉
OID_MARKER_DESC  = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 6, 1, 1)   # prtMarkerDescription
OID_MARKER_LIFE  = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 7, 1, 1)   # prtMarkerLifeExpectancy (页)
OID_MARKER_TYPE  = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 8, 1, 1)   # prtMarkerType
OID_MARKER_LEVEL = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 9, 1, 1)   # prtMarkerLevel (-3..100)
OID_MARKER_COUNT = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 4, 1, 1)   # prtMarkerCounter

# prtMarkerLevel 语义（RFC 3805）
LEVEL_UNKNOWN  = -3
LEVEL_BUSY     = -2
LEVEL_NA       = -1

# CUPS 状态位 → 耗材含义
REASON_MAP = {
    "toner-low":     ("墨粉不足", "low"),
    "toner-empty":   ("墨粉已尽", "empty"),
    "opc-life-low":  ("硒鼓寿命低", "low"),
    "drum-life-low": ("硒鼓寿命低", "low"),
    "waste-tank-near-full": ("废粉仓将满", "low"),
    "marker-supply-low":    ("耗材不足", "low"),
    "marker-supply-empty":  ("耗材已尽", "empty"),
    "cover-open":           ("盖板打开", "info"),
    "media-empty":          ("缺纸", "info"),
    "media-jam":            ("卡纸", "info"),
    "paused":               ("已暂停", "info"),
}

# Samsung USB 状态字典（来自 EPM 抓包重组的 <StatusMonitorInfo> XML）
_CN_STATES = {
    "Ready": "就绪", "PowerSave": "睡眠", "Printing": "打印中",
    "Warmingup": "预热中", "Recovery": "恢复中", "RecoveryTemperature": "定影器升温",
    "RecoveryLSU": "LSU 恢复中",
    "ManualLoad": "手动进纸", "FirstPaperEmpty": "缺纸", "ManualEmpty": "手动进纸缺纸",
    "PaperJam1": "卡纸1", "PaperJam2": "卡纸2",
    "PaperJam0Tray1": "纸盒1卡纸", "PaperJam0Manual": "手动进纸卡纸",
    "CoverOpen": "盖板打开", "OutbinFull": "出纸口满",
    "FuserHighError": "定影器过热", "FuserLowError": "定影器温度低",
    "FuserOpenError": "定影器盖打开",
    "LSUHsyncError": "LSU 水平同步错误", "LSUMotorError": "LSU 电机错误",
    "UsbCableOff": "USB 断开", "NetworkCableOff": "网络断开",
    "TonerLow": "碳粉不足", "TonerEmptyReplaceToner": "碳粉用尽",
    "TonerExhaustedReplaceToner": "粉盒寿命终止",
    "TonerKitNotInstK": "未安装粉盒", "InvalidTonerKitK": "粉盒不兼容",
    "NonGenuineTonerReplaceToner": "非原装粉盒",
    "NonGenuineTonerReplaceToner1": "非原装粉盒(2)",
}


# ---------------------------------------------------------------- SNMP
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(reversed(out))


def _ber_int(n):
    if n == 0:
        return b"\x02\x01\x00"
    neg = n < 0
    n = abs(n)
    body = bytearray()
    while n:
        body.append(n & 0xFF)
        n >>= 8
    body = bytearray(reversed(body))
    if neg:
        raise NotImplementedError("negative integer not needed here")
    if body[0] & 0x80:
        body.insert(0, 0)
    return b"\x02" + _ber_len(len(body)) + bytes(body)


def _ber_oid(oid):
    if len(oid) < 2:
        raise ValueError("oid too short")
    body = bytearray([40 * oid[0] + oid[1]])
    for v in oid[2:]:
        stack = [v & 0x7F]
        v >>= 7
        while v:
            stack.append(0x80 | (v & 0x7F))
            v >>= 7
        body.extend(reversed(stack))
    return b"\x06" + _ber_len(len(body)) + bytes(body)


def _tl(tag, val):
    return bytes([tag]) + _ber_len(len(val)) + val


def _decode(data, pos=0):
    """极简 BER 解码：返回 (tag, value_bytes, next_pos)"""
    if pos >= len(data):
        raise ValueError("truncated")
    tag = data[pos]
    pos += 1
    ln = data[pos]
    pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + ln], pos + ln


def _parse_int(b):
    if not b:
        return 0
    v = int.from_bytes(b, "big")
    if b[0] & 0x80:              # 有符号
        v -= 1 << (8 * len(b))
    return v


def snmp_get(ip, oid, community="public", timeout=1.5, port=161):
    """SNMP v1 GET。成功返回 int/str/None，网络失败抛异常。"""
    req_id = int(time.time()) & 0x7FFFFFFF
    varbind = _tl(0x30, _ber_oid(oid) + b"\x05\x00")
    pdu_body = _ber_int(req_id) + _ber_int(0) + _ber_int(0) + varbind
    pdu = _tl(0xA0, pdu_body)
    msg = _tl(0x30, _ber_int(0) + _tl(0x04, community.encode()) + pdu)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (ip, port))
        data, _ = s.recvfrom(2048)
    finally:
        s.close()

    # 解析响应：SEQUENCE -> version, community, PDU -> ... -> varbind 列表
    # 注意 _decode 返回的 value 是新 buffer，必须从 0 开始解析，不能沿用外层 pos
    _, body, _ = _decode(data, 0)
    pos = 0
    _, _, pos = _decode(body, pos)          # version
    _, _, pos = _decode(body, pos)          # community
    _, pdu, _ = _decode(body, pos)          # PDU（独立 buffer）

    ppos = 0
    _, _, ppos = _decode(pdu, ppos)         # request-id
    _, err, ppos = _decode(pdu, ppos)       # error-status
    _, _, ppos = _decode(pdu, ppos)         # error-index
    if _parse_int(err) != 0:
        raise RuntimeError(f"SNMP error-status={_parse_int(err)}")

    _, vbl, ppos = _decode(pdu, ppos)       # varbind list
    _, vb, _ = _decode(vbl, 0)
    _, _, vpos = _decode(vb, 0)             # OID
    tag, val, _ = _decode(vb, vpos)         # value
    if tag == 0x02:                         # INTEGER
        return _parse_int(val)
    if tag == 0x04:                         # OCTET STRING
        return val.decode("utf-8", "replace").strip("\x00")
    if tag == 0x06:                         # OID（回显）
        return val
    if tag == 0x05:                         # NULL → 无值
        return None
    return val


# ---------------------------------------------------------------- 配置与记录
def _cfg_path(pkgvar):
    return os.path.join(pkgvar, "supplies.json")


def load_config(pkgvar):
    p = _cfg_path(pkgvar)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return {"ip": "", "community": "public", "manual": {}}


def save_config(pkgvar, cfg):
    p = _cfg_path(pkgvar)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    json.dump(cfg, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(tmp, p)
    return cfg


# ---------------------------------------------------------------- 查询
def _snmp_supplies(ip, community):
    """走 SNMP 拿真实耗材。返回 list，拿不到抛异常。"""
    items = []
    desc = snmp_get(ip, OID_MARKER_DESC, community)
    level = snmp_get(ip, OID_MARKER_LEVEL, community)
    life = snmp_get(ip, OID_MARKER_LIFE, community)
    count = snmp_get(ip, OID_MARKER_COUNT, community)

    if level is None:
        raise RuntimeError("SNMP 未返回墨粉余量")

    if isinstance(level, int):
        if level in (LEVEL_UNKNOWN, LEVEL_NA):
            pct, note = None, "打印机未报告余量"
        elif level == LEVEL_BUSY:
            pct, note = None, "打印机忙"
        else:
            pct = max(0, min(100, level))
            note = ""
    else:
        pct, note = None, str(level)

    name = (desc or "墨粉").strip() or "墨粉"
    item = {
        "name": name, "kind": "toner", "source": "snmp",
        "percent": pct, "note": note,
    }
    if isinstance(life, int) and life > 0:
        item["life_pages"] = life
    if isinstance(count, int) and count >= 0:
        item["printed_pages"] = count
        if isinstance(life, int) and life > 0:
            item["life_used_percent"] = max(0, min(100, round(count * 100 / life)))
    items.append(item)
    return items


def _reason_supplies(reasons):
    """从 CUPS printer-state-reasons 提取耗材相关状态。"""
    if not reasons or reasons.strip() in ("", "none"):
        return []
    out = []
    for tok in re.split(r"[\s,]+", reasons.strip()):
        if tok in REASON_MAP:
            label, sev = REASON_MAP[tok]
            if sev in ("low", "empty"):
                out.append({
                    "name": label, "kind": "supply", "source": "state",
                    "percent": 0 if sev == "empty" else None,
                    "note": f"CUPS 状态: {tok}", "reason": tok, "severity": sev,
                })
    return out


def _manual_supplies(cfg):
    """手动登记：换粉时记下基线页数，之后更新当前页数即可估算余量。"""
    m = cfg.get("manual") or {}
    if not m:
        return []
    life = m.get("life_pages") or 0
    base = m.get("baseline_pages")
    last = m.get("last_pages")
    changed = m.get("changed_date") or ""
    name = m.get("name") or "墨粉"

    if life and isinstance(last, int) and isinstance(base, int):
        used = max(0, last - base)
        left = max(0, life - used)
        pct = max(0, min(100, round(left * 100 / life)))
        note = f"换粉 {changed}，已用 {used} / {life} 页"
        if m.get("last_update"):
            note += f"（页数更新于 {m['last_update']}）"
        return [{
            "name": name, "kind": "toner", "source": "manual",
            "percent": pct, "note": note,
            "life_pages": life, "printed_pages": used, "remaining_pages": left,
        }]
    if changed:
        return [{
            "name": name, "kind": "toner", "source": "manual",
            "percent": None,
            "note": f"换粉 {changed}，请填入打印机面板的当前总页数",
        }]
    return []


def query(pkgvar, printer_state_reasons=""):
    """汇总耗材信息。返回 dict。"""
    cfg = load_config(pkgvar)
    result = {
        "ok": True,
        "source": "none",
        "items": [],
        "printer_ip": cfg.get("ip") or "",
        "hint": "",
        "usb": None,
    }

    # 0) USB 专有协议（Samsung SCX-4623 逆向自 EPM 抓包；无需网络、无需驱动）
    #    协议只给状态（正常/低粉/空粉/卡纸…），不给百分比
    try:
        import usb_supply as _usb
        u = _usb.query(pkgvar)
        if u.get("ok"):
            result["usb"] = u
            states = u.get("states") or []
            toner = u.get("toner")
            pct = u.get("percent")
            if toner:
                result["items"].append({
                    "name": "碳粉盒 (MLT-D1053L)", "kind": "toner", "source": "usb",
                    "percent": pct, "note": toner.get("note") or toner.get("state", ""),
                })
                result["source"] = "usb"
                result["hint"] = "数据来自打印机 USB 实时状态（厂商协议）"
                return result
            # 无耗材告警 → 报告"正常"（正向信息，比手动估算可信）
            if states:
                result["items"].append({
                    "name": "碳粉盒 (MLT-D1053L)", "kind": "toner", "source": "usb",
                    "percent": pct,
                    "note": "状态正常（%s）" % "、".join(_CN_STATES.get(s, s) for s in states),
                })
                if result["source"] == "none":
                    result["source"] = "usb"
                    result["hint"] = "数据来自打印机 USB 实时状态（厂商协议）"
    except Exception:
        # 无权限/设备占用/协议变化 → 静默降级到下一级
        pass

    # 1) SNMP（配了 IP 才试；USB 直连机走不到这里）
    ip = (cfg.get("ip") or "").strip()
    if ip:
        try:
            result["items"] = _snmp_supplies(ip, cfg.get("community") or "public")
            result["source"] = "snmp"
            result["hint"] = f"数据来自打印机 SNMP（{ip}）"
            return result
        except Exception as e:
            result["hint"] = f"SNMP 查询失败：{e}"

    # 2) CUPS 状态位
    st = _reason_supplies(printer_state_reasons)
    if st:
        result["items"].extend(st)
        result["source"] = "state"
        if not result["hint"]:
            result["hint"] = "来自 CUPS 状态位（仅能判断是否低粉/缺粉，无百分比）"

    # 3) 手动登记
    man = _manual_supplies(cfg)
    if man:
        result["items"].extend(man)
        if result["source"] == "none":
            result["source"] = "manual"
            if not result["hint"]:
                result["hint"] = "来自手动登记（按打印机面板页数估算）"

    if result["source"] == "none":
        result["hint"] = "尚未登记耗材：点「登记换粉」填入面板页数即可开始估算"
    return result


def update_manual(pkgvar, payload):
    """登记/更新手动耗材记录。"""
    cfg = load_config(pkgvar)
    m = dict(cfg.get("manual") or {})
    action = (payload.get("action") or "").strip()

    if action == "reset":
        # 换新粉：以当前页数为基线
        pages = payload.get("pages")
        if not isinstance(pages, int) or pages < 0:
            raise ValueError("pages 必须是非负整数（打印机面板的总计页数）")
        life = payload.get("life_pages")
        if not isinstance(life, int) or life <= 0:
            raise ValueError("life_pages 必须是正整数（粉盒额定寿命，页）")
        m = {
            "name": (payload.get("name") or "").strip() or "墨粉",
            "life_pages": life,
            "baseline_pages": pages,
            "last_pages": pages,
            "changed_date": time.strftime("%Y-%m-%d"),
            "last_update": time.strftime("%Y-%m-%d"),
        }
    elif action == "update":
        pages = payload.get("pages")
        if not isinstance(pages, int) or pages < 0:
            raise ValueError("pages 必须是非负整数")
        if not m.get("life_pages"):
            raise ValueError("尚未登记换粉，请先执行 reset")
        if pages < (m.get("baseline_pages") or 0):
            raise ValueError("当前页数小于换粉基线，数据不合理")
        m["last_pages"] = pages
        m["last_update"] = time.strftime("%Y-%m-%d")
    elif action == "clear":
        m = {}
    else:
        raise ValueError("action 必须是 reset / update / clear")

    cfg["manual"] = m
    save_config(pkgvar, cfg)
    return m
