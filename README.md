# fn-scx4623

飞牛 fnOS 的第三方 FPK 应用 —— **Samsung SCX-4623fw 一体机**的打印 / 复印 / 扫描控制台。

> ⚠️ **本应用只适配 SCX-4623fw（USB 直连）**
> 耗材状态查询用的是从这台机器上逆向出来的 **Samsung 私有 USB vendor 协议**，
> 其他型号的签名与语义可能不同，请勿直接套用。

## 功能

| 功能 | 说明 |
|---|---|
| 打印 | 上传 PDF/图片 → CUPS 队列出纸 |
| 复印 | 用 `scanimage` 采稿后直接送打印队列 |
| 扫描 | 单页/多页 → PDF，带缩略图 |
| 扫描预览 | 网页端直接看历史扫描件（可删除/下载） |
| **耗材余量** | 碳粉盒剩余百分比、页数估算、换粉登记 |
| **实时状态** | 30 种机器状态码（就绪/睡眠/卡纸/碳粉/硬件故障…） |

- Web UI 端口 `8372`，纯 Python 标准库实现，**零第三方依赖**
- 应用以 `fn-scx4623` 系统用户运行，加入 `lp` / `scanner` 组

## 耗材数据源（优先级）

```
0. USB 厂商协议   ← 真实设备状态 + 剩余百分比（本项目核心）
1. SNMP (Printer MIB)   —— 需要打印机接入网络，本机型无 WiFi 时休眠
2. CUPS printer-state-reasons   —— toner-low / toner-empty 等布尔状态
3. 手动登记         —— 读面板页数做线性估算
```

## USB 协议（逆向自 macOS usbmon 抓包）

抓取 EPM（Easy Printer Manager）与机器的通信后还原出三条查询，均为
vendor control transfer（`bmRequestType = 0xC1`，`wIndex = 0x0100`）：

| 用途 | SETUP | 返回 |
|---|---|---|
| 状态字典 | `bRequest=0x0D wValue=0 wLength=8` → 元数据<br>`bRequest=0x0D wValue=1..N wLength=255` → 分片 | XML（约 4.8 KB），含全部状态签名 |
| 当前状态 | `bRequest=0x02 wValue=0 wLength=8` | 8 字节状态 + 剩余百分比 |
| 固件版本 | `bRequest=0x56 wLength=64` | ASCII 固件信息 |

**8 字节状态结构**：

```
byte0-2  主状态码        ← 核心识别
byte3    子状态码        ← 区分同主码的细分（FF = 无子状态）
byte4    剩余百分比      ← 0..100，越界不采信
byte5-7  保留（恒 0）
```

**状态匹配**（两类）：

- 带 `<Mask>` 的签名 → 严格按 Mask 比较，`00` = 忽略该字节
- 只有 `<Status>` 的签名 → `0xFF` 为通配字节，其余必须相等

字典 XML 里共 **30 个状态**：正常/工作 8、耗材 7、纸张 7、硬件故障 5、盖板连接 3。

> 这份协议**没有公开文档**，签名与字段含义由抓包数据反推、并经真机验证。
> `byte4 = 百分比` 的判定依据：抓包 48/48 次恒定、真机实测一致、
> 且 `byte4-7` 在所有状态签名中均为 `FF`（通配、不参与状态匹配）。

## 安装

1. 下载 [`fn-scx4623.fpk`](./fn-scx4623.fpk)（或自行 `fnpack build`）
2. fnOS **应用中心 → 手动安装** → 选择 `.fpk`
3. 打开应用，首页即可看到打印机/扫描仪状态

或使用 fnOS CLI（需先 `login`）：

```bash
trim-cli app install-fpk ./fn-scx4623.fpk --volume-id <卷ID> --yes
```

## 打包

```bash
fnpack build          # 产出 fn-scx4623.fpk
```

打包前记得清理杂物（否则会被原样打进包）：

```bash
find . -name '__pycache__' -type d -exec rm -rf {} +
find . -name '*.pyc' -delete
```

## 目录结构

```
manifest               应用元信息（appname / version / 端口）
config/privilege       运行用户与附加组（lp, scanner）
config/resource        数据共享（扫描件）
app/server/server.py   HTTP 服务（标准库，无依赖）
app/server/supplies.py 耗材查询（USB → SNMP → CUPS → 手动）
app/server/usb_supply.py  Samsung USB 协议实现
app/ui/index.html      单文件 Web UI
cmd/main               生命周期脚本（start/stop/status）
test_usb.py            USB 协议真机自检脚本
```

## 已知边界

- 协议只提供**状态档位 + 百分比**，没有按颜色分列的余量（本机是黑白机，单粉盒）
- 打印机进入 `PowerSave` 后，`TonerLow` 会被睡眠状态覆盖，唤醒后恢复上报
- 精确页数与余量仍以机器面板为准：
  `Menu → System Setup → Maintenance → Supplies Life`
