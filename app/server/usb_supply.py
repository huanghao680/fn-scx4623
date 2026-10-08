"""Samsung USB 状态查询（usbfs ioctl，零依赖）

协议逆向自 SCX-4623fw 的 EPM 抓包（macOS usbmon, 7222 包）：

  ① 状态字典  C1 0D wValue=0      wIndex=0x0100 wLen=8   → 8 字节元数据(总长)
               C1 0D wValue=1..N   wIndex=0x0100 wLen=255  → XML 分片
  ② 当前状态  C1 02 wValue=0       wIndex=0x0100 wLen=8   → 8 字节状态
  ③ 固件版本  C1 56 wValue=0       wIndex=0x0100 wLen=64  → ASCII

状态判定：字典里每个 <Status> 节点带 <Mask>/<Status>，拿当前 8 字节按掩码比对。
"""
import ctypes
import fcntl
import os
import re
import struct
import xml.etree.ElementTree as ET

USBDEVFS_CONTROL = 0xC0185500  # _IOWR('U',0,struct usbdevfs_ctrltransfer): dir=3(READ|WRITE), size=24
USB_REQ_TIMEOUT_MS = 3000

VENDOR_ID = "04e8"
PRODUCT_ID = "3434"

# 首字节 0xC1 = IN | vendor | endpoint1
BM_RT_IN = 0xC1
W_INDEX = 0x0100


class _CtrlTransfer(ctypes.Structure):
    _fields_ = [
        ("bRequestType", ctypes.c_uint8),
        ("bRequest", ctypes.c_uint8),
        ("wValue", ctypes.c_uint16),
        ("wIndex", ctypes.c_uint16),
        ("wLength", ctypes.c_uint16),
        ("timeout", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


def find_device(vid=VENDOR_ID, pid=PRODUCT_ID):
    """动态找 usbfs 路径（枚举号会变，不能写死）"""
    root = "/sys/bus/usb/devices"
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        try:
            with open(os.path.join(d, "idVendor")) as f:
                v = f.read().strip()
            with open(os.path.join(d, "idProduct")) as f:
                p = f.read().strip()
        except OSError:
            continue
        if v == vid and (pid is None or p == pid):
            try:
                bus = int(open(os.path.join(d, "busnum")).read().strip())
                dev = int(open(os.path.join(d, "devnum")).read().strip())
            except (OSError, ValueError):
                continue
            path = "/dev/bus/usb/%03d/%03d" % (bus, dev)
            if os.path.exists(path):
                return path
    return None


def control_in(dev_path, b_request, w_value=0, w_length=64, timeout=USB_REQ_TIMEOUT_MS):
    """发 vendor IN control transfer，返回 bytes"""
    buf = ctypes.create_string_buffer(w_length)
    ctrl = _CtrlTransfer(
        BM_RT_IN, b_request, w_value, W_INDEX, w_length, timeout,
        ctypes.cast(buf, ctypes.c_void_p),
    )
    # 走 libc.ioctl（可传含指针的结构体；fcntl.ioctl 不接受 ctypes 对象）
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
    libc.ioctl.restype = ctypes.c_int
    fd = os.open(dev_path, os.O_RDWR)
    try:
        ret = libc.ioctl(fd, USBDEVFS_CONTROL, ctypes.byref(ctrl))
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return buf.raw[:max(ret, 0)]
    finally:
        os.close(fd)


def get_status_bytes(dev_path):
    """当前 8 字节状态（EPM 轮询用的就是它）"""
    return control_in(dev_path, 0x02, w_value=0x0000, w_length=8)


def get_firmware(dev_path):
    raw = control_in(dev_path, 0x56, w_value=0x0000, w_length=64)
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def get_status_xml(dev_path, cache_path=None, max_chunks=64):
    """拉完整状态字典 XML（19 片 × 255B ≈ 4.8KB）"""
    if cache_path and os.path.exists(cache_path) and os.path.getsize(cache_path) > 500:
        try:
            with open(cache_path, "rb") as f:
                return f.read()
        except OSError:
            pass

    meta = control_in(dev_path, 0x0D, w_value=0, w_length=8)
    total = struct.unpack_from("<I", meta, 0)[0] if len(meta) >= 4 else 0
    if not (0 < total < 1_000_000):
        total = 0

    parts = []
    for i in range(1, max_chunks + 1):
        chunk = control_in(dev_path, 0x0D, w_value=i, w_length=255)
        if not chunk:
            break
        parts.append(chunk)
        if total and sum(len(c) for c in parts) >= total:
            break
        if len(chunk) < 255:
            break

    xml = b"".join(parts)
    if cache_path and xml:
        try:
            with open(cache_path, "wb") as f:
                f.write(xml)
        except OSError:
            pass
    return xml


def parse_state_sigs(xml_bytes):
    """解析字典 → {name: (mask[8], sig[8])}

    两类状态：
      A) 有 <Mask>：严格按 Mask 比较（00=忽略该字节）
      B) 只有 <Status>：签名里的 0xFF 是通配字节（忽略），其余必须相等
         —— 这类状态靠 byte0-2 主状态码 + byte3 子码区分
    """
    txt = xml_bytes.decode("utf-8", "replace")
    txt = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", txt)
    sigs = {}

    def nums(s):
        return [int(x, 16) for x in re.findall(r"\[([0-9A-Fa-f]{2})\]", s)]

    # A) <StateName ...><Mask>..</Mask><Status>..</Status></StateName>
    for m in re.finditer(
        r"<([A-Za-z][\w]*)\b[^>]*>\s*<Mask>(.*?)</Mask>\s*<Status>(.*?)</Status>\s*</\1>",
        txt, re.S,
    ):
        name, mask_s, sig_s = m.group(1), m.group(2), m.group(3)
        mask, sig = nums(mask_s), nums(sig_s)
        if len(mask) == 8 and len(sig) == 8:
            sigs[name] = (bytes(mask), bytes(sig))

    # B) <StateName STRING=".."><Status>..</Status></StateName>  （无 Mask）
    for m in re.finditer(
        r"<([A-Za-z][\w]*)\s+STRING=\"[^\"]*\"[^>]*><Status>(.*?)</Status></\1>",
        txt,
    ):
        name, sig_s = m.group(1), m.group(2)
        sig = nums(sig_s)
        if len(sig) == 8 and name not in sigs:
            # 0xFF → 通配（不比较），其余字节必须相等
            mask = bytes(0x00 if b == 0xFF else 0xFF for b in sig)
            sigs[name] = (mask, bytes(sig))
    return sigs


def match_state(status8, sigs):
    """按掩码比对，返回匹配的状态名列表"""
    if not status8 or len(status8) < 8:
        return []
    hit = []
    for name, (mask, sig) in sigs.items():
        ok = True
        for i in range(min(8, len(mask))):
            if mask[i] and status8[i] != sig[i]:
                ok = False
                break
        if ok:
            hit.append(name)
    return hit


# 字典拉取失败时的兜底签名（来自本次抓包重组的 XML，SCX-4623fw）
FALLBACK_SIGS = {
    "Ready":                (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x81\x01\x01\xff\xff\xff\xff\xff"),
    "PowerSave":            (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x81\x01\x03\xff\xff\xff\xff\xff"),
    "Printing":             (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x81\x01\x04\xff\xff\xff\xff\xff"),
    "Warmingup":            (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x81\x01\x05\xff\xff\xff\xff\xff"),
    "TonerLow":             (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x82\x05\x02\x00\xff\xff\xff\xff"),
    "TonerEmptyReplaceToner": (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x82\x05\x1f\xff\xff\xff\xff\xff"),
    "TonerExhaustedReplaceToner": (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x84\x05\x21\xff\xff\xff\xff\xff"),
    "TonerKitNotInstK":     (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x84\x05\x07\x04\xff\xff\xff\xff"),
    "InvalidTonerKitK":     (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x84\x05\x06\x04\xff\xff\xff\xff"),
    "CoverOpen":            (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x84\x08\x03\x00\xff\xff\xff\xff"),
    "PaperJam1":            (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x84\x03\x01\x08\xff\xff\xff\xff"),
    "ManualEmpty":          (b"\x00\xff\xff\x00\x00\x00\x00\x00", b"\x84\x03\x02\x06\xff\xff\xff\xff"),
}

TONER_STATES = {
    "TonerLow": ("low", "碳粉不足，准备新粉盒"),
    "TonerEmptyReplaceToner": ("empty", "碳粉用尽，需更换"),
    "TonerExhaustedReplaceToner": ("dead", "粉盒寿命终止，必须更换"),
    "TonerKitNotInstK": ("missing", "未安装碳粉盒"),
    "InvalidTonerKitK": ("invalid", "碳粉盒不兼容"),
}


def query(pkgvar, cache=True):
    """返回 {ok, source, status, states, toner, firmware, error}"""
    out = {
        "ok": False, "source": "usb", "status_hex": "", "states": [],
        "toner": None, "firmware": "", "error": "",
    }
    dev = find_device()
    if not dev:
        out["error"] = "未找到 Samsung USB 设备"
        return out
    try:
        st = get_status_bytes(dev)
    except OSError as e:
        out["error"] = "USB 打开/查询失败: %s" % e
        return out

    out["status_hex"] = st.hex(" ")
    out["ok"] = True

    # 余量百分比：byte4。依据 —— 抓包 48/48 次恒为 10，真机实测 10，
    # 与 EPM 界面显示的 10% 一致；byte4-7 在所有状态签名里均为 0xFF（通配，
    # 不参与状态匹配），即它们是与状态无关的"别的数据"。
    # 只在 0..100 内采信，越界视为非百分比（避免误读）。
    out["percent"] = st[4] if len(st) > 4 and st[4] <= 100 else None

    sigs = None
    if cache:
        xml = get_status_xml(dev, cache_path=os.path.join(pkgvar, "state_dict.xml"))
        if xml:
            sigs = parse_state_sigs(xml)
    if not sigs:
        sigs = FALLBACK_SIGS

    states = match_state(st, sigs)
    out["states"] = states

    for s in states:
        if s in TONER_STATES:
            out["toner"] = {"key": TONER_STATES[s][0], "state": s,
                            "note": TONER_STATES[s][1]}
            break

    try:
        out["firmware"] = get_firmware(dev)
    except OSError:
        pass
    return out
