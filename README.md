# group-request-handler

MaiBot 群聊申请处理插件 — 监听群聊邀请，管理员审核 + 白名单管理 + 群列表查询。

## 功能

- **群邀请审核**：收到加群邀请时通知管理员，支持通过/拒绝
- **白名单管理**：白名单内的群自动放行，不在白名单的可配置自动退群
- **群列表查询**：查看机器人当前所在群列表
- **审核中静默**：审核中的群聊消息自动静默处理

## 安装

将 `group-request-handler` 目录放入 MaiBot 的 `plugins/` 目录下。

## 配置

复制 `config.example.toml` 为 `config.toml` 并修改：

```toml
[admin]
admin_qqs = ["你的QQ号"]

[whitelist]
enforce_whitelist = true
group_whitelist = ["群号1", "群号2"]
```

## 依赖

- `aiohttp >= 3.9.0`

## 许可证

MIT
