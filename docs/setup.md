# 本机构建、安装和首次授权

## 先确认条件

安装官方 MotionPro 与 MotionProOTP，通过官方工具绑定自己的令牌，并在 MotionPro 中完成目标站点和默认配置。确认已有授权访问的账号可用。

本项目不会安装厂商软件、签发账号或修改官方令牌绑定。厂商适配对不匹配的二进制构建直接拒绝；先阅读 [兼容性说明](compatibility.md)。

如果已运行另一套 Guard，先在其本身的管理流程中协调停用。首次安装器检测到其他 MotionPro Guard 登录任务时会拒绝安装或启用，不替换它们。

## 本地配置和签名

复制 `project.example.json` 为 `project.local.json`，只填写 DNS 网关主机名，例如 `vpn.example.org` 的实际替代值。不要包含 `https://`、端口、用户名或密码。构建值只注入临时编译目录；提交的 Swift 配置始终保留示例值。

在 macOS“钥匙串访问”中使用证书助理创建自己的代码签名证书，或使用自己的有效代码签名身份。保持同一身份，不将证书私钥导出到仓库。可用 `security find-identity -v -p codesigning` 在自己的终端查看证书指纹。

```bash
python3 build.py --config project.local.json --signing-identity YOUR_CERTIFICATE_SHA1
python3 install.py --install 'dist/MotionPro Guard OSS.app'
python3 install.py --enable-jobs
open -a "$HOME/Applications/MotionPro Guard OSS.app" 'motionpro-guard-oss://open'
```

安装器不启动 VPN，不替换已有 app，不迁移旧钥匙串数据。首次策略关闭自动恢复，登录任务启用后仍保留该关闭状态。操作系统的打开验证由使用者通过正常本机流程处理；安装器不清除隔离属性或修改全局安全设置。

## 三项本机设置

在 Guard 管理界面中完成：

1. 从唯一匹配的 MotionPro 配置导入静态凭据。凭据保存在公开版专用的钥匙串服务中。
2. 授权当前固定签名构建读取专用钥匙串条目。需要修复旧条目访问时，Guard 生成校验当前 CDHash 的本地脚本；使用者在自己的系统提示中输入钥匙串密码。密码不交给聊天、Guard 参数或项目配置。
3. 选择自己已绑定的 `VSite.plist`，保持解锁和官方 OTP 页可读。文件所在容器可能由系统使用随机标识，不硬编码容器路径。Guard 在最多 75 秒内跨至少两个周期比较口令，全部一致才保存绑定令牌。

完成后检查：

```bash
"$HOME/Applications/MotionPro Guard OSS.app/Contents/MacOS/MotionProGuard" --check-keychain
"$HOME/Applications/MotionPro Guard OSS.app/Contents/MacOS/MotionProGuard" --check-offline-otp
```

这些诊断不提交登录，也不打印密码、种子或 OTP。刚启动、系统时间变化或靠近换码边界时可能需要稍后再检查。确认条件就绪后，通过管理界面开启“自动恢复”。

## 启动、停止和升级边界

`python3 install.py` 默认仅查看安装/任务状态。

- `--enable-jobs` 加载公开版自己的两个登录任务，保留策略开关。
- `--disable-jobs` 在恢复不忙且取得恢复锁后卸载这两个任务，保留 app、隧道、钥匙串与所有预算历史；用于明确的人工接管。
- `--install APP` 只做首次安装。有已有 app 时拒绝覆盖。

本公开包没有自动升级器。更新二进制后可能需要对新构建重新做本机钥匙串授权；不要沿用原作者证书、清空重试历史或覆盖正在执行的恢复事务。

公开版预算协调本公开版主程序与备用脚本，不自动迁移其他 Guard 的预算。更换应用标识或数据目录不能用于规避已知失败暂停；已有实例的迁移需要单独保留和核对历史。

## 锁屏和睡眠

登录任务运行于已登录的 macOS Aqua 会话。已核对的离线 TOTP 不依赖 OTP 窗口或日常辅助功能读码权限，能够在锁屏状态计算。实际锁屏登录是否成功必须自然验收。

关机、完全休眠、尚未登录桌面或钥匙串不可读时不会继续执行恢复。VPN 恢复不自动恢复已断开的 SSH 会话或业务 token；依赖任务必须自行核查并重连。
