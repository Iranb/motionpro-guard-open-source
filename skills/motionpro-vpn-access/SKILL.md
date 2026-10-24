---
name: motionpro-vpn-access
description: 检查 macOS MotionPro VPN、MotionPro Guard 自动登录与离线 OTP 状态，在已有授权范围内协调限次人工备用恢复，再继续依赖 VPN 的网站、SSH 或 HPC 任务。用于 VPN 断线、自动登录失败、小组件状态异常、校内资源连接超时，以及解释或验收自动恢复流程。先识别实际产品和本机配置；普通公网 SSH 和本地文件任务不强制连接 VPN。
---

# MotionPro VPN 接入与自动恢复

先恢复网络前置条件，再继续原任务。使用本 skill 不等于获准提交或取消作业、结束进程、删除数据、变更账号或修改系统网络与安全设置。

## 先确认环境与授权

1. 识别当前产品；不是 MotionPro 时停止使用本适配器。不要因用户说“VPN”就假定客户端。
2. 读取 [环境设置](references/environment.md)。如果存在本机专用 `references/local-environment.md`，先读它；此文件和 `environment.local.json` 属于私有配置，不上传。
3. 将下文 `SKILL_ROOT` 替换为已加载 skill 的实际绝对路径。不依赖当前工作目录，也不把字面占位符交给 shell。
4. 区分请求：状态检查只运行只读命令；已有授权的同账号同网关恢复沿用授权；新网关、权限、令牌导入、安装或安全设置须按当前请求与工具规则处理。公开配置示例不授予任何权限。
5. 保留现有 VPN、NAS、科研任务、桥接服务及远程会话。已连接时不做断线或重连测试，不修改路由、DNS、代理或全局电源策略。

## 只读预检

```bash
python3 "SKILL_ROOT/scripts/preflight.py"
python3 "SKILL_ROOT/scripts/manual_attempt.py" status
python3 "SKILL_ROOT/scripts/handover.py" inspect
```

预检只调用已安装厂商的 `vpn_cmdline getstatus`，读取白名单状态和策略；不读密码、OTP、原始日志或钥匙串。厂商退出码 2/6 可能代表已连接，不直接当作 shell 失败。

| 厂商状态 / 预检结果 | 下一步 |
| --- | --- |
| 2/6，`tunnel_connected_check_target` | 保持连接，验证本次目标资源，继续原任务。 |
| 1/3/4，`wait_for_transition` | 约 10 秒后复核，等待当前过程，不叠加登录。 |
| 0/7，`recovery_needed` | 约 10 秒复核，持续离线约 30 秒后评估恢复。 |
| 5 或无法确认，`inspect_client` | 用实时界面核实产品、模式和状态，不当作断线重启。 |

脚本退出码：0=隧道连接；2=离线；3=切换中；4=无法确认。`environment.configured=false` 时只获得厂商隧道状态，不能推断某套 Guard 的健康，更不能向默认目录写新预算。

区分隧道、Guard 自动连接机制、本地网络和远端服务。`guard.fresh=true` 只说明快照时间新。连接状态下 `credentialReady` / `offlineOTPReady` 为 null 可能是本轮未检查，不等于缺失。公网可达不能证明目标 VPN 网关或业务可达。

## 优先观察 Guard 自动恢复

读取 [自动流程与 OTP 同步](references/automatic-flow.md)，结合本轮状态判断：

- 核对心跳、`lastProgressAt`、`recoveryBusy`、`profileMutationActive`、`stateDeadline`、策略开关和暂停预算。
- Guard 1.6.5 通过原生日志/网络事件触发检查；`automaticCheckMode=login_expiry` 表示成功登录后 24 小时加 2 分钟的补充检查，平时不轮询。`scheduled_idle=true` 不代表卡住，也不代表隧道仍在线；不要擅自恢复周期查询。
- 按阶段等待：持续断线确认约 30 秒；默认 `official_profile` 等待安全 OTP 窗口，提交后观察隧道最多 180 秒；前置检查另计。
- 有进度且未过本阶段截止时间时继续观察。陈旧状态、阶段超时、钥匙串/绑定失败或预算暂停须说明具体阻塞。
- 默认 `official_profile` 使用官方已保存密码和每次新读取的官方令牌，不依赖旧 Guard 钥匙串或口令窗口。旧后端仅在条目不存在时允许窗口备用；拒绝访问或绑定不匹配不能悄悄换来源。
- 看护任务只恢复 Guard 自身；不要把它描述成会重启 VPN 服务，也不要假定锁屏取码成功就已证明锁屏登录。

## 必要时接管人工备用恢复

只在持续离线、自动恢复已停止或有明确阻塞、且恢复处于当前授权范围时，完整读取 [人工恢复与交接](references/manual-recovery.md)。

使用显式交接脚本保存原启用状态、卸载已核对的 Guard 自己的登录任务、取得共用恢复锁后暂停策略。KeepAlive 会拉起单纯退出的 app；不要用“退出一下”代替交接。交接拒绝时保留现场，不强杀或直接改计数。

用当前可用且获授权的电脑操作工具，在解锁桌面核实真实表单、网关、账号和官方 OTP 绑定。密码与新 OTP 仅保留在本机工具变量中。提交前预留共享预算，更新第二密码，提交一次，再结算实际结果。

滚动一小时最多 2 次，连续 2 次已提交失败暂停。自动与人工共用已有策略，未知结果保守计为失败；不清空历史或新建另一命名空间绕过预算。人工成功不增加 Guard 自动归属计数。

## 验证目标并继续原任务

- 网页：检查用户所需的具体站点；HTTP 可达、VPN 认证和业务登录分开报告。
- SSH：使用已有准确别名和授权做一次有超时的只读验证，如 `ssh -o BatchMode=yes -o ConnectTimeout=8 -o ConnectionAttempts=1 KNOWN_ALIAS true`。不扫描主机或修改主机密钥信任。
- DNS 失败、TCP 超时、拒绝连接、SSH `Permission denied` 分别诊断；隧道已连不等于所有业务可用。
- HPC：继续原来的平台技能和原账号认证。VPN 会话与门户 token 属于不同层次；断线前可能已提交的操作先查原 job ID、receipt 或 PID，避免重复。
- 解释稳定性或锁屏无人值守能力时，读 [证据与自然验收](references/evidence.md)。不给安装、取码诊断或单次成功附加未经验证的结论。

报告实时 VPN 状态与时间、目标实际验证结果、自动/人工恢复归属、原任务是否继续，以及具体阻塞。样本不足就说明观察窗口和缺失证据。用户的 Mac 密码由本人输入系统提示，不发送到聊天。
