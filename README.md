# ESP32 广告过滤安装向导 1.0

面向 ESP32-C3 4MB 的中文 Windows 10/11 x64 安装助手，帮助使用者完成备份刷写、Wi-Fi 配网、小米路由器 DHCP DNS 配置与广告过滤验收。

**当前为预览版**：引擎测试和现网 DNS 验证通过；新通用固件刷写/配网、真实路由器写入和鼠标界面仍需进一步实机验收，见 [验证记录](docs/validation.md)。

- [下载 Windows EXE](release/ESP32-AdBlock-Wizard.exe?raw=true)（约 21 MB，无需 Python）
- [下载源码包](release/ESP32-Wizard-Source.zip?raw=true)
- [SHA256 校验](release/ESP32-Wizard-SHA256.txt)

中文 Windows 10/11 x64 原生桌面程序。分发时只需 `ESP32-AdBlock-Wizard.exe`，用户无需安装 Python。首次启动在当前用户的 `%LOCALAPPDATA%\ESP32AdBlockWizard` 释放组件，备份、日志和诊断报告也在该目录。

## 使用顺序

1. **准备**：插入 ESP32-C3 4MB 开发板，使用数据线，检查环境。已安装好的设备可跳过刷写，直接发现设备。
2. **刷写**：选串口、识别芯片。确认后先读取完整 4MB 原固件及 SHA256，再擦除、写入并验证五个镜像。备份失败不会擦除。无法连接时按住 BOOT，点 RESET，再松开 BOOT。首次可能需要安装开发板厂商的 USB 串口驱动。
3. **配网**：保持 USB 接电脑，读取设备信息。记录 `setup_hotspot`、`ap_password`、`web_password`、`ota_password`。连接 C3-AdBlock-* 热点后访问 http://192.168.4.1/ ，输入家庭 2.4GHz Wi-Fi。电脑重新连接家庭 Wi-Fi 后发现设备。网页用户名为 admin。凭据仅显示在结果窗口，结果临时文件采用 Windows 当前用户 DPAPI 加密，读取后删除。
4. **路由器**：填写网关与管理密码，点击“登录并预览”。核对设备 IP、MAC、现有 DHCP 与计划变更，再“确认应用”。自动配置适用于兼容小米 MiWiFi API 的单个 /24 家庭网段；不识别的路由器请使用手动引导，不能承诺所有小米型号/固件均支持。程序保留已有绑定、地址范围、租约和网关，添加设备绑定并将 DHCP DNS1 指向设备、DNS2 留空。修改前保存配置，修改后回读。保存时可能短暂断网。恢复原 DNS 会保留设备 IP 绑定；若 DNS 已被别人改动会停止，避免覆盖。
5. **验收**：移到路由器 USB 口供电，电脑/手机重新连接 Wi-Fi。完整验收检查规则加载、广告 A/AAAA、正常域名以及 Windows 默认解析器。其他终端仍须分别验证，单台电脑通过不代表全家每台设备通过。

USB 只负责供电，设备通过 Wi-Fi 提供 DNS。断电会影响使用它作为唯一 DNS 的客户端上网；恢复供电或在路由器恢复原 DNS 即可。不要把公网 DNS 填入备用 DNS，否则客户端可能绕过过滤。程序不会自动更改 IPv6、浏览器安全 DNS、VPN 或手机私人 DNS；这些可能绕过过滤。

## 能力边界

- DNS 域名过滤可阻止独立广告/跟踪域名；不能可靠清除 YouTube 视频广告和与正文共用域名的广告。
- 固件预置 119631 条规则，上游 DNS 223.5.5.5。不同规则可能误拦截，可通过设备面板管理白名单。
- 仅支持 ESP32-C3、4MB，DIO 40MHz，自定义双 OTA 分区；不会尝试写入其它芯片或容量。
- 不包含本人的 Wi-Fi、路由器密码、个人设备固件或原固件备份。配网热点、网页和 OTA 密码由每台设备首次启动独立生成并保存 NVS，USB 随时可重新读取。能接触 USB 的人能读到设备管理信息。
- 原固件备份含设备原有私密配置，请妥善保管，不要公开。需要恢复原固件时，可用 Espressif esptool 在下载模式下将完整备份写回地址 0，务必核对同一块板和 SHA256。本向导提供备份目录入口，不提供一键恢复原固件。
- 自动路由器操作失败后不要反复盲点；查看备份并登录后台核对实际状态，再决定重试或恢复 DNS。

## 编译方式

界面使用 **Free Pascal 3.2.2 的 DelphiUnicode 模式**编译为原生 Win64 程序；Object Pascal 源码调用 Win32 API，无 VCL/LCL 依赖。操作引擎使用 Python/esptool，经 PyInstaller 冻结后内嵌于 EXE。商业 Embarcadero Delphi 编译器的兼容性尚未验证。

## 从源码构建

需 Python 3.11.4（本次构建版本）、Free Pascal 3.2.2 Win64（含 windres）。在 Windows PowerShell 中进入源码目录：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\build.ps1 -FpcRoot 'D:\your-fpc\3.2.2' -Python '.\.venv\Scripts\python.exe'
```

构建脚本先执行测试，再打包引擎、资源、原生程序，输出 build\ESP32-AdBlock-Wizard.exe。`firmware/manifest.json` 含五个镜像的地址和 SHA256。

如需重新编译固件，`firmware-source` 是不含个人信息的完整源文件，使用 PlatformIO 的 c3 环境，先 build 再 buildfs。使用上游构建依赖版本并保留 DIO/40MHz 与 partitions.csv；把输出复制到 firmware 并重新计算 manifest SHA256，再打包 EXE。不能用个人 secrets.h 替换后分发。`build.ps1` 默认直接使用已编译好的通用镜像。

本向导新增源码按 GPL-2.0-or-later 提供，见 LICENSE；第三方组件继续适用各自许可。

## 组件与许可

设备固件基于 https://github.com/M-Abozaid/esp32-c3-adblock，保留原 LICENSE 与源码。串口烧录使用 Espressif esptool（GPL-2.0-or-later）：https://github.com/espressif/esptool 。操作引擎所用 requests（Apache-2.0）、pyserial（BSD）、PyInstaller（GPL 附带分发例外）由对应项目授权。工具包中 licenses 保留已安装组件的许可原文；Redistribution 时应继续提供源码和许可。

验证范围请查看 docs/validation.md，未做过的真实硬件测试不会标为通过。
