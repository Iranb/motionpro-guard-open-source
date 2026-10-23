# 本机构建、安装和设置

## 前置条件

安装官方 MotionPro 与 MotionProOTP，绑定自己的令牌。在官方客户端完成一次正常登录，保存静态密码，并将目标 VPN 设为默认站点。仅使用已核对的客户端构建，见 [兼容性](compatibility.md)。

如果已经运行其他 Guard，先通过该程序的管理流程协调停用。首次安装器检测到其他 Guard 登录任务时拒绝安装或启用，不替换它们。不要并行运行其他自动登录脚本。

## 网关和签名

复制 `project.example.json` 为 `project.local.json`，只填写 DNS 网关主机名。不要包含协议、端口、用户名或密码。该文件被 Git 忽略；构建只向临时目录注入本机值。

在 macOS“钥匙串访问”的证书助理中创建自己的代码签名证书，或使用已有的有效签名身份。保持同一身份；私钥始终保留在自己的钥匙串中。可通过 `security find-identity -v -p codesigning` 查看本机证书指纹。

```bash
python3 build.py --config project.local.json --signing-identity YOUR_CERTIFICATE_SHA1
python3 install.py --install 'dist/MotionPro Guard OSS.app'
python3 install.py --enable-jobs
open -a "$HOME/Applications/MotionPro Guard OSS.app" 'motionpro-guard-oss://open'
```

构建不安装或启动应用。安装不启动 VPN，首次策略关闭自动恢复。安装器不覆盖已有应用、迁移旧凭据或更改系统安全设置。

## 官方数据源

1. 在管理页点击“选择官方 OTP 数据源”。选择自己已绑定的 `VSite.plist`。容器可能使用系统生成的随机名称，不要套用其他电脑的路径。
2. Guard 只读验证当前默认站点、已保存的加密静态密码、目标网关和令牌格式，只保存数据文件位置和端口。不会重新绑定 OTP、复制种子到项目目录或提交登录。
3. 点击“检查登录条件”，确认官方密码和当前令牌可读。如果 macOS 要求访问其他 App 数据，由本人通过系统设置授权。调用方终端能读取文件，不代表 launchd 的 Guard 已获相同权限，必须检查后台程序的结果。
4. 点击“立即检查”。已有成功认证日志时会记录最近成功登录时间。无法读取可信时间时，先用官方客户端完成正常登录，再检查；程序不把观察器启动时间当成登录时间。
5. 开启“预计到期后自动恢复”，核对管理页显示的下次时间。

默认 `official_profile` 流程直接使用官方已保存密码，不需要导入旧 Guard 专用钥匙串条目或保持 OTP 窗口打开。

```bash
"$HOME/Applications/MotionPro Guard OSS.app/Contents/MacOS/MotionProGuard" --check-official-profile
```

此命令只输出就绪布尔值，不登录或打印口令。文件配置位于 `~/Library/Application Support/MotionProGuardOSS/official-connector/config.json`，只在本机保留，不作为迁移材料。

## 定时恢复和桌面小组件

成功登录后 24 小时加 2 分钟进行一次状态检查。仍在线则保留连接并安排下一天；确认离线后使用新的 OTP 启动官方客户端一次。平时不轮询，旧看护助手没有周期触发。

右键桌面 → 编辑小组件 → 搜索 MotionPro Guard OSS。小组件显示定时恢复状态；点击打开管理页。提前意外断线可点击“立即检查”，但单次点击仍遵守持续断线确认与尝试预算，不绕过这些要求。

## 启动、停止和升级

`python3 install.py` 默认仅查看安装和任务状态。

- `--enable-jobs` 加载公开版自己的主任务和无周期触发的看护任务，保留恢复开关。
- `--disable-jobs` 在恢复空闲且取得恢复锁后卸载这两个任务，保留隧道、数据和全部预算历史。
- `--install APP` 只做首次安装，拒绝覆盖已有应用。

没有自动升级器。已有安装的升级和跨标识迁移需要先协调原程序与未完成事务，再保留预算和本机设置；不要清空策略来绕过暂停。旧钥匙串后端的授权工具只服务于其专用条目，不是默认官方配置流程的必需步骤。

## 锁屏与睡眠

Guard 运行于已登录的 macOS Aqua 会话。后台取码不依赖 OTP 窗口；完整锁屏登录仍须按 [验收说明](acceptance.md) 实测。

休眠、关机或未登录桌面时不执行恢复。唤醒后重新安排已到期计划，不修改全局电源设置。VPN 恢复后仍需独立核对依赖它的 SSH、网页或 HPC 认证。
