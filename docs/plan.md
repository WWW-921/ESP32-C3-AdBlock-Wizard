# ESP32 AdBlock Wizard Implementation Plan

> **For agentic workers:** Use executing-plans for implementation in this session.

**Goal:** 可分发的中文原生 Windows 完整向导。
**Architecture:** Object Pascal Win32 GUI + 内嵌操作引擎和通用固件。JSON 请求与结果，后台线程。
**Tech Stack:** Delphi-compatible Object Pascal, Win32 API, Python/esptool/requests/pyserial, ESP32 Arduino。
**Spec:** design.md

## Global Constraints
- 不包含任何用户 Wi-Fi、路由器会话或个人管理密码。
- 仅识别并刷写 ESP32-C3 4MB；成功备份才允许写入；DIO 40MHz。
- 每台设备独立随机凭据；路由器修改必须预览、确认、备份、回读。
- 成功必须包括规则加载、广告拦截、正常解析和系统 DNS 路径；没有验收不显示成功。

## Review Focus
- 错误串口/芯片/容量；备份失败不得继续。
- 伪造设备网页和无效网关；限制本地私网目标。
- DHCP 大网段和已有绑定；不允许猜测配置字段。
- 日志和请求文件不能泄露密码。
- DNS 不可达、规则未加载、正常域名被拦截不能算通过。

## Tasks
- [x] 1. 恢复可用 Pascal 编译器；编译 smoke 程序核对 PE 类型。
- [x] 2. 写操作引擎测试：目标验证、DNS 数据包、固件完整性、路由器参数/恢复、失败刷写，先红后绿。
- [x] 3. 实现 engine.py：串口识别/备份/刷写、配网串口读取、发现、DNS、路由器预览/应用/恢复。
- [x] 4. 创建不含个人凭据的通用固件，NVS 随机管理密码，编译并核对镜像。
- [x] 5. 实现 Wizard.dpr 原生 GUI、后台执行、日志、确认、资源释放，编译并做 UI 验证。
- [x] 6. 打包引擎和固件进 EXE，执行只读真实设备及模拟刷写/路由器测试，独立代码审核修复后交付。

## Completion limits
已完成实现、编译、联调、只读现网验证与代码复核。视觉/鼠标验收受桌面工具超时影响，新固件硬件端到端和真实路由器写入未执行；详见 validation.md。
