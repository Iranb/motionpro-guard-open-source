# 环境配置与安装 skill

本 skill 可独立复制到当前 Codex 的技能目录；默认是 `~/.codex/skills/motionpro-vpn-access`，设置了 `CODEX_HOME` 时以实际 Codex 目录为准。不要复制个人配置或缓存到公共仓库。

1. 先识别已安装 MotionPro、厂商命令及实际 Guard。没有 Guard 时可以只读检查隧道，但不能虚构自动恢复状态或创建一套新预算。要新增自动连接系统，应使用仓库的构建/首次安装流程。
2. 新公开版环境：将 skill 根目录的 `environment.example.json` 复制为 `environment.local.json`。只有已安装公开版 app、两个现有 LaunchAgent 和现有策略匹配时才可接管。示例网关不用于真实登录。
3. 已有私有版环境：依据现有 app 的 Info.plist、两个 LaunchAgent 的 Label/ProgramArguments 和现有支持目录填写同样五个字段。保留原命名空间、预算、钥匙串和令牌。不要同时启用公开版与私有版。
4. 将目标资源、已有授权和历史验收结论存入本机专用 `references/local-environment.md`。它不是公共模板，也不是授权的替代品。公开同步时显式排除。
5. 运行只读 preflight / manual status / handover inspect。交接会再次严格验证应用签名、bundle ID 和任务参数；版本/配置不同会拒绝，不自动创建或替换任务。

配置只接受：`support_directory`（用户 Application Support 下的单层目录名）、`app_relative_path`（用户 Applications 下的 app）、`bundle_identifier`、`main_job_label`、`watchdog_job_label`。拒绝额外字段、路径穿越和符号链接配置。不要填写账号、密码、种子、OTP、证书私钥或历史日志。

公共源与本机安装共用相同脚本；本机 profile 单独保存。读取本机环境文件时不要展示原始账号、密文配置、钥匙串数据或 OTP 文件。只为当前故障读取必要元数据。

本 skill 随仓库按 GNU GPL v3 或更新版本发布。许可证全文在仓库根目录 LICENSE；厂商应用不包含在 skill 中。
