#!/usr/bin/env python3
"""
fn-scx4623 - Samsung SCX-4623fw print/copy/scan/preview + toner status (USB vendor protocol)

仅依赖 Python 标准库 + 系统命令(lp / scanimage / convert)。
数据目录: $TRIM_PKGVAR/scans/<id>/{pageN.png, thumbN.png, meta.json}
"""

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

warnings.filterwarnings("ignore", category=DeprecationWarning)
try:
    import cgi  # Python 3.13 移除；缺库时打印接口会给出明确错误
except ImportError:  # pragma: no cover
    cgi = None

# ---------------------------------------------------------------- 配置
PKGVAR = os.environ.get("TRIM_PKGVAR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
APPDEST = os.environ.get("TRIM_APPDEST") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# UI 目录：fnpack 打包后 app/ 内容可能被平铺，也可能保留 app/ 层 —— 逐一探测
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import supplies as _supplies
_UI_CANDS = [
    os.path.normpath(os.path.join(_HERE, "..", "ui")),      # 平铺: <root>/server/server.py + <root>/ui
    os.path.normpath(os.path.join(APPDEST, "app", "ui")),   # 保留 app/ 层
    os.path.normpath(os.path.join(APPDEST, "ui")),
]
UI_DIR = next((c for c in _UI_CANDS if os.path.isfile(os.path.join(c, "index.html"))),
              _UI_CANDS[0])
SCANS_DIR = os.path.join(PKGVAR, "scans")
TMP_DIR = os.environ.get("TRIM_PKGTMP") or "/tmp"

PRINTER = (os.environ.get("WIZARD_PRINTER") or "").strip()
if not PRINTER:
    pfile = os.path.join(PKGVAR, "printer.name")
    if os.path.exists(pfile):
        try:
            PRINTER = open(pfile, encoding="utf-8").read().strip()
        except Exception:
            PRINTER = ""

MAX_UPLOAD = 100 * 1024 * 1024      # 100 MB
MAX_PAGES = 30
SCAN_TIMEOUT = 300
PRINT_TIMEOUT = 120

SCAN_LOCK = threading.Lock()
INDEX_LOCK = threading.Lock()
INDEX_FILE = os.path.join(SCANS_DIR, "index.json")

ID_RE = re.compile(r"^[a-f0-9\-]{8,64}$")
SAFE_NAME = re.compile(r"[^0-9A-Za-z._一-鿿-]+")


# ---------------------------------------------------------------- 工具
def run(cmd, timeout=60, cwd=None, binary=False):
    """执行命令，返回 (rc, stdout_bytes_or_str, stderr)"""
    try:
        p = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        return 127, b"" if binary else "", str(e)
    except subprocess.TimeoutExpired:
        return 124, b"" if binary else "", "命令超时 (%ss)" % timeout
    out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    return p.returncode, out, err


def jdump(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


def read_index():
    with INDEX_LOCK:
        if not os.path.exists(INDEX_FILE):
            return []
        try:
            data = json.load(open(INDEX_FILE, encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []


def write_index(items):
    with INDEX_LOCK:
        os.makedirs(SCANS_DIR, exist_ok=True)
        tmp = INDEX_FILE + ".tmp"
        json.dump(items, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        os.replace(tmp, INDEX_FILE)


# ---------------------------------------------------------------- 硬件状态
def printer_info():
    global PRINTER
    if not PRINTER:
        # 自动发现第一台打印机
        rc, out, _ = run(["lpstat", "-p"], timeout=10)
        m = re.search(r"^printer\s+(\S+)", out or "", re.M)
        if m:
            PRINTER = m.group(1)
    info = {"name": PRINTER or None, "ok": False, "state": "unknown",
            "detail": "", "reasons": "", "printing": False}
    if not PRINTER:
        info["detail"] = "未配置打印机"
        return info
    rc, out, err = run(["lpstat", "-p", PRINTER], timeout=10)
    text = (out + err).strip()
    info["detail"] = text
    if rc == 0:
        info["ok"] = True
        if "is printing" in text:
            info["state"] = "printing"
            info["printing"] = True
        elif "is idle" in text:
            info["state"] = "idle"
        elif "not accepting" in text:
            info["state"] = "disabled"
        else:
            info["state"] = "ready"
    else:
        info["state"] = "error"

    # printer-state-reasons 原样透传（paused / media-empty / toner-low …），
    # 不自行翻译成「在线」——见 skill: print-scan-services.md「状态透传的坑」。
    # 该字段在 `lpoptions -p` 的 key=value 流里，不在 `lpstat -l -p`。
    rc2, out2, _ = run(["lpoptions", "-p", PRINTER], timeout=10)
    m = re.search(r"printer-state-reasons=(.+?)(?=\s[\w.-]+=[^ ]|$)", out2 or "")
    if m:
        info["reasons"] = m.group(1).strip()

    # 注意：不用 lpstat -o 统计「当前作业」——它列出所有未完成作业，
    # 含历史卡死的僵尸单，会误报负载。是否正在打印以 lpstat -p 的 is printing 为准。
    return info


def scanner_info():
    rc, out, err = run(["scanimage", "-L"], timeout=20)
    devs = []
    for m in re.finditer(r"device\s+`([^']+)'(?:\s+is\s+(.*))?", (out or "") + (err or "")):
        devs.append({"id": m.group(1), "name": (m.group(2) or "").strip()})
    return {"ok": rc == 0 and bool(devs), "devices": devs}


# ---------------------------------------------------------------- 扫描
def do_scan(dpi=200, mode="Color", pages=1, title="", want_pdf=True):
    """执行扫描，返回扫描记录 dict；失败抛 RuntimeError"""
    info = scanner_info()
    if not info["devices"]:
        raise RuntimeError("未检测到扫描仪，请检查 USB 连接与电源")

    dpi = str(int(dpi))
    if dpi not in ("75", "100", "150", "200", "300", "600"):
        dpi = "200"
    if mode not in ("Color", "Gray", "Lineart"):
        mode = "Color"
    pages = max(1, min(int(pages), MAX_PAGES))

    sid = uuid.uuid4().hex[:12]
    out_dir = os.path.join(SCANS_DIR, sid)
    os.makedirs(out_dir, exist_ok=True)

    base = ["scanimage", "-d", info["devices"][0]["id"],
            "--resolution", dpi, "--format=png", f"--mode={mode}"]

    with SCAN_LOCK:
        if pages == 1:
            # scanimage 默认把图像写到 stdout，重定向落盘
            rc, out, err = run(base, timeout=SCAN_TIMEOUT, binary=True)
            if rc != 0 or not out:
                shutil.rmtree(out_dir, ignore_errors=True)
                raise RuntimeError(f"扫描失败: {err.strip() or '无输出'}")
            with open(os.path.join(out_dir, "page1.png"), "wb") as f:
                f.write(out)
            produced = ["page1.png"]
        else:
            rc, out, err = run(base + [f"--batch=page%d.png", f"--batch-count={pages}"],
                               timeout=SCAN_TIMEOUT, cwd=out_dir)
            produced = [f for f in sorted(os.listdir(out_dir))
                        if re.match(r"^page\d+\.png$", f)]
            if rc != 0 or not produced:
                shutil.rmtree(out_dir, ignore_errors=True)
                raise RuntimeError(f"扫描失败: {err.strip() or '未生成图像'}")

    # 归一化页名 page1.png ...
    pages_out = []
    for i, fn in enumerate(sorted(produced, key=lambda x: int(re.search(r"\d+", x).group())),
                           start=1):
        dst = f"page{i}.png"
        if fn != dst:
            os.replace(os.path.join(out_dir, fn), os.path.join(out_dir, dst))
        # 缩略图
        try:
            run(["convert", os.path.join(out_dir, dst), "-resize", "420x420>",
                 os.path.join(out_dir, f"thumb{i}.png")], timeout=60)
        except Exception:
            pass
        pages_out.append(dst)

    pdf_rel = None
    if want_pdf:
        pdf_path = os.path.join(out_dir, "scan.pdf")
        rc, _, err = run(["convert"] + [os.path.join(out_dir, p) for p in pages_out] + [pdf_path],
                         timeout=180)
        if rc == 0 and os.path.exists(pdf_path):
            pdf_rel = "scan.pdf"

    meta = {
        "id": sid,
        "time": int(time.time()),
        "title": (title or "").strip() or f"扫描_{time.strftime('%Y%m%d_%H%M')}",
        "type": "scan",
        "dpi": int(dpi),
        "mode": mode,
        "pages": len(pages_out),
        "pdf": pdf_rel,
        "size": sum(os.path.getsize(os.path.join(out_dir, p)) for p in pages_out),
    }
    json.dump(meta, open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    items = read_index()
    items.insert(0, meta)
    write_index(items[:500])
    return meta


# ---------------------------------------------------------------- 打印
def do_print(path, copies=1, printer=None):
    pr = printer or PRINTER
    if not pr:
        raise RuntimeError("未配置打印机")
    if not os.path.exists(path):
        raise RuntimeError("待打印文件不存在")
    copies = max(1, min(int(copies), 99))
    cmd = ["lp", "-d", pr]
    if copies > 1:
        cmd += ["-n", str(copies)]
    cmd.append(path)
    rc, out, err = run(cmd, timeout=PRINT_TIMEOUT)
    if rc != 0:
        raise RuntimeError(f"提交打印失败: {err.strip() or out.strip() or '未知错误'}")
    job = (out or "").strip()
    return {"job": job, "printer": pr, "copies": copies}


def do_copy(dpi=200, mode="Gray", pages=1, copies=1):
    """复印 = 扫描 → 直接送打印"""
    meta = do_scan(dpi=dpi, mode=mode, pages=pages, title=f"复印_{time.strftime('%H%M%S')}",
                   want_pdf=False)
    out_dir = os.path.join(SCANS_DIR, meta["id"])
    files = sorted([f for f in os.listdir(out_dir) if re.match(r"^page\d+\.png$", f)],
                   key=lambda x: int(re.search(r"\d+", x).group()))
    if not files:
        raise RuntimeError("扫描无图像，无法复印")
    results = []
    for f in files:
        results.append(do_print(os.path.join(out_dir, f), copies=copies))
    meta["printed"] = True
    return {"scan": meta, "print": results}


# ---------------------------------------------------------------- 路径安全
def safe_scan_dir(sid):
    if not ID_RE.match(sid or ""):
        raise RuntimeError("非法 ID")
    d = os.path.join(SCANS_DIR, sid)
    if not os.path.isdir(d):
        raise RuntimeError("记录不存在")
    return d


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "fn-scx4623/1.2"
    protocol_version = "HTTP/1.1"

    # ---- 基础 ----
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = jdump(body)
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _err(self, code, msg):
        self._send(code, {"ok": False, "error": str(msg)})

    def _json_body(self, limit=1 << 20):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > limit:
            raise RuntimeError("请求体为空或过大")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise RuntimeError(f"JSON 解析失败: {e}")

    # ---- GET ----
    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            if path in ("/", "/index.html"):
                return self._static("index.html")

            if path == "/api/status":
                return self._send(200, {
                    "ok": True,
                    "printer": printer_info(),
                    "scanner": scanner_info(),
                    "scans": len(read_index()),
                    "port": self.server.server_address[1],
                })

            if path == "/api/scans":
                return self._send(200, {"ok": True, "items": read_index()})

            if path == "/api/supplies":
                try:
                    reasons = printer_info().get("reasons", "")
                except Exception:
                    reasons = ""
                return self._send(200, _supplies.query(PKGVAR, reasons))

            m = re.match(r"^/api/scans/([^/]+)/page/(\d+)$", path)
            if m:
                return self._scan_file(m.group(1), f"page{m.group(2)}.png")

            m = re.match(r"^/api/scans/([^/]+)/thumb/(\d+)$", path)
            if m:
                return self._scan_file(m.group(1), f"thumb{m.group(2)}.png")

            m = re.match(r"^/api/scans/([^/]+)/download$", path)
            if m:
                return self._download(m.group(1), qs)

            return self._err(404, "not found")
        except Exception as e:
            return self._err(500, e)

    def _static(self, name):
        p = os.path.join(UI_DIR, name)
        if not os.path.isfile(p):
            return self._err(404, "UI 不存在")
        data = open(p, "rb").read()
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else \
                mimetypes_guess(p)
        return self._send(200, data, ctype)

    def _scan_file(self, sid, fname):
        d = safe_scan_dir(sid)
        p = os.path.join(d, fname)
        if not os.path.isfile(p):
            return self._err(404, "文件不存在")
        return self._send(200, open(p, "rb").read(), "image/png")

    def _download(self, sid, qs):
        d = safe_scan_dir(sid)
        fmt = (qs.get("fmt", ["pdf"])[0] or "pdf").lower()
        meta = {}
        mp = os.path.join(d, "meta.json")
        if os.path.exists(mp):
            meta = json.load(open(mp, encoding="utf-8"))
        if fmt == "pdf" and os.path.exists(os.path.join(d, "scan.pdf")):
            p = os.path.join(d, "scan.pdf")
            fname = (meta.get("title") or sid) + ".pdf"
            ctype = "application/pdf"
        else:
            # 打包 PNG（多页时合并为 PDF，单页直接给 PNG）
            pngs = sorted([f for f in os.listdir(d) if re.match(r"^page\d+\.png$", f)],
                          key=lambda x: int(re.search(r"\d+", x).group()))
            if not pngs:
                return self._err(404, "无图像")
            if len(pngs) == 1 and fmt == "png":
                p = os.path.join(d, pngs[0])
                fname = (meta.get("title") or sid) + ".png"
                ctype = "image/png"
            else:
                p = os.path.join(d, "scan.pdf")
                if not os.path.exists(p):
                    rc, _, err = run(["convert"] + [os.path.join(d, x) for x in pngs] + [p],
                                     timeout=180)
                    if rc != 0:
                        return self._err(500, f"生成 PDF 失败: {err.strip()}")
                fname = (meta.get("title") or sid) + ".pdf"
                ctype = "application/pdf"
        data = open(p, "rb").read()
        fname = urllib.parse.quote(SAFE_NAME.sub("_", fname))
        return self._send(200, data, ctype, {"Content-Disposition":
                                              f"attachment; filename*=UTF-8''{fname}"})

    # ---- POST ----
    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path

            if path == "/api/scan":
                b = self._json_body()
                meta = do_scan(dpi=b.get("dpi", 200), mode=b.get("mode", "Color"),
                               pages=b.get("pages", 1), title=b.get("title", ""))
                return self._send(200, {"ok": True, "item": meta})

            if path == "/api/supplies/manual":
                b = self._json_body()
                try:
                    m = _supplies.update_manual(PKGVAR, b)
                except ValueError as e:
                    return self._err(400, e)
                return self._send(200, {"ok": True, "manual": m})

            if path == "/api/copy":
                b = self._json_body()
                r = do_copy(dpi=b.get("dpi", 200), mode=b.get("mode", "Gray"),
                            pages=b.get("pages", 1), copies=b.get("copies", 1))
                return self._send(200, {"ok": True, **r})

            if path == "/api/print":
                return self._upload_print()

            if path == "/api/scans/reprint":
                b = self._json_body()
                sid = b.get("id")
                d = safe_scan_dir(sid)
                pngs = sorted([f for f in os.listdir(d) if re.match(r"^page\d+\.png$", f)],
                              key=lambda x: int(re.search(r"\d+", x).group()))
                if not pngs:
                    return self._err(404, "该记录无图像")
                res = [do_print(os.path.join(d, f), copies=b.get("copies", 1)) for f in pngs]
                return self._send(200, {"ok": True, "print": res})

            return self._err(404, "not found")
        except Exception as e:
            return self._err(500, e)

    def _upload_print(self):
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return self._err(400, "需要 multipart/form-data")
        if cgi is None:
            return self._err(500, "当前 Python 缺少 cgi 模块，无法接收上传文件")
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_UPLOAD:
            return self._err(413, "文件过大或为空")
        form = cgi.FieldStorage(fp=io.BytesIO(self.rfile.read(n)),
                                headers=self.headers,
                                environ={"REQUEST_METHOD": "POST",
                                         "CONTENT_TYPE": ctype,
                                         "CONTENT_LENGTH": str(n)})
        f = form["file"] if "file" in form else None
        if f is None or not getattr(f, "filename", ""):
            return self._err(400, "缺少文件字段 file")
        raw = f.file.read()
        if not raw:
            return self._err(400, "文件为空")
        orig = os.path.basename(f.filename)
        ext = os.path.splitext(orig)[1].lower() or ".bin"
        safe = SAFE_NAME.sub("_", os.path.splitext(orig)[0])[:60] or "print"
        os.makedirs(os.path.join(TMP_DIR, "fn-scx4623-uploads"), exist_ok=True)
        path = os.path.join(TMP_DIR, "fn-scx4623-uploads",
                            f"{int(time.time())}_{uuid.uuid4().hex[:6]}{ext}")
        with open(path, "wb") as out:
            out.write(raw)
        try:
            copies = int((form.getvalue("copies") or 1))
            res = do_print(path, copies=copies)
        except Exception as e:
            try:
                os.unlink(path)
            except Exception:
                pass
            return self._err(500, e)
        # 留一份到扫描历史，便于预览
        try:
            sid = uuid.uuid4().hex[:12]
            od = os.path.join(SCANS_DIR, sid)
            os.makedirs(od, exist_ok=True)
            shutil.copy(path, os.path.join(od, "original" + ext))
            if ext == ".pdf":
                shutil.copy(path, os.path.join(od, "scan.pdf"))
                rc, _, _ = run(["pdftoppm", "-png", "-r", "150", path,
                                os.path.join(od, "page")], timeout=180)
                for fn in [x for x in os.listdir(od) if x.startswith("page") and x.endswith(".png")]:
                    m = re.search(r"(\d+)", fn)
                    if m:
                        os.replace(os.path.join(od, fn),
                                   os.path.join(od, f"page{int(m.group(1))}.png"))
            elif ext in (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"):
                shutil.copy(path, os.path.join(od, "page1.png"))
            pngs = sorted([x for x in os.listdir(od) if re.match(r"^page\d+\.png$", x)],
                          key=lambda x: int(re.search(r"\d+", x).group()))
            for i, pn in enumerate(pngs, 1):
                run(["convert", os.path.join(od, pn), "-resize", "420x420>",
                     os.path.join(od, f"thumb{i}.png")], timeout=60)
            if pngs:
                meta = {"id": sid, "time": int(time.time()),
                        "title": safe, "type": "print", "dpi": 0, "mode": "-",
                        "pages": len(pngs),
                        "pdf": "scan.pdf" if os.path.exists(os.path.join(od, "scan.pdf")) else None,
                        "size": os.path.getsize(path)}
                json.dump(meta, open(os.path.join(od, "meta.json"), "w", encoding="utf-8"),
                          ensure_ascii=False, indent=1)
                items = read_index()
                items.insert(0, meta)
                write_index(items[:500])
        except Exception:
            pass
        try:
            os.unlink(path)
        except Exception:
            pass
        return self._send(200, {"ok": True, **res})

    # ---- DELETE ----
    def do_DELETE(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            m = re.match(r"^/api/scans/([^/]+)$", path)
            if not m:
                return self._err(404, "not found")
            sid = m.group(1)
            d = safe_scan_dir(sid)
            shutil.rmtree(d, ignore_errors=True)
            write_index([x for x in read_index() if x.get("id") != sid])
            return self._send(200, {"ok": True})
        except Exception as e:
            return self._err(500, e)


def mimetypes_guess(p):
    if p.endswith(".css"):
        return "text/css; charset=utf-8"
    if p.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if p.endswith(".png"):
        return "image/png"
    return "application/octet-stream"


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("TRIM_SERVICE_PORT") or 8372))
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    os.makedirs(SCANS_DIR, exist_ok=True)

    info = printer_info()
    scan = scanner_info()
    print(f"[fn-scx4623] listening on {args.host}:{args.port}", flush=True)
    print(f"[fn-scx4623] printer={info['name']} ({info['state']})", flush=True)
    print(f"[fn-scx4623] scanner={'ok' if scan['ok'] else 'NOT FOUND'}", flush=True)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
