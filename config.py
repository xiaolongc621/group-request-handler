"""群聊申请处理插件 — 配置模型。"""

from __future__ import annotations

from typing import ClassVar, List

from maibot_sdk import Field, PluginConfigBase


class PluginSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "插件开关"
    __ui_order__: ClassVar[int] = 0

    enabled: bool = Field(default=True, description="是否启用本插件")
    config_version: str = Field(default="1.0.0", json_schema_extra={"disabled": True, "hidden": True, "label": "配置版本", "order": 99})


class AdminSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "管理员"
    __ui_order__: ClassVar[int] = 1

    admin_qqs: List[str] = Field(
        default_factory=list,
        description="管理员 QQ 号列表。群邀请通知推送到这里，只有管理员能使用管理命令。",
    )


class WebhookSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "Webhook 监听"
    __ui_order__: ClassVar[int] = 2

    host: str = Field(default="127.0.0.1", description="监听地址")
    port: int = Field(default=18081, ge=1, le=65535, description="监听端口，需与 NapCat HTTP 客户端上报端口一致")
    path: str = Field(default="/maibot/group_request", description="HTTP 路径")
    secret: str = Field(default="", json_schema_extra={"input_type": "password"}, description="可选，对应 NapCat HTTP 客户端 token")


class WhitelistSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "白名单"
    __ui_order__: ClassVar[int] = 3

    enforce_whitelist: bool = Field(
        default=True,
        description="开启后，bot 不在白名单内的群中不会发消息，且会自动退群",
    )
    group_whitelist: List[str] = Field(
        default_factory=list,
        description="允许 bot 加入的群号白名单。空列表 = 不限制。",
    )
    check_interval_seconds: int = Field(
        default=60, ge=10, le=3600,
        description="白名单巡检间隔（秒），发现不在白名单的群会自动退出",
    )
    leave_on_invite_reject: bool = Field(
        default=True,
        description="管理员拒绝邀请后，bot 如果在群内则自动退出",
    )


class GroupRequestHandlerConfig(PluginConfigBase):
    plugin: PluginSection = Field(default_factory=PluginSection)
    admin: AdminSection = Field(default_factory=AdminSection)
    webhook: WebhookSection = Field(default_factory=WebhookSection)
    whitelist: WhitelistSection = Field(default_factory=WhitelistSection)
