# Changelog

## 1.6.5

- Recover from native MotionPro log and system network events without periodic idle status polling. Keep the login-expiry check as a fallback.
- Coalesce event bursts, confirm known disconnection for about 30 seconds, and retain the bounded observation window when vendor status is temporarily unreadable. Unknown and desktop-only states never authorize login.
- Preserve later client control settings when cleaning up a temporary OTP. Keep the saved static password unchanged, and retain transactions on unsupported changes or credential conflicts.
- Show disconnect recovery and the expiry fallback in the widget, with errors and holds taking priority.
- Support an expiring, explicitly authorized single-use hourly test grant. Consume it durably on the next Guard submission while preserving history, manual control, and consecutive-failure protection.
- Add native file-event, observation-window, transaction, widget, and budget tests. A locally configured 1.6.5 candidate completed one locked-screen event recovery on a separate Mac with one submission and at least 60 seconds of stable tunnel observations. Natural session expiry and fresh public-edition authentication still require validation.

## 1.6.1

- 按最近成功登录后 24 小时加 2 分钟安排恢复，移除空闲期间的 VPN 轮询和周期看护查询。
- 使用官方客户端已保存的静态密码与每次新读取的官方 OTP 绑定，不依赖口令窗口。
- 集成桌面小组件、上次登录时间和下次恢复计划。
- 提供本机官方数据源选择入口，保持公开版独立配置与使用者自己的持久签名。
- 保留共享尝试预算，正确清除已结算的官方登录预留记录。
- 补充配置事务、安全状态判定、定时计算和重启后结算的合成测试。
