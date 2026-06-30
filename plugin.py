"""
群聊申请处理插件。
参考 whitefox_friend-request-handler 架构，实现群邀请审核 + 白名单管理。
采用 HookHandler 实现审核中群的入站/出站消息静默（同 group_muter_plugin 方案）。
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import time
from hashlib import sha1
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp import web

from maibot_sdk import CONFIG_RELOAD_SCOPE_SELF, Command, HookHandler, MaiBotPlugin
from maibot_sdk.types import ErrorPolicy, HookMode, HookOrder

from .config import GroupRequestHandlerConfig


class GroupRequestHandlerPlugin(MaiBotPlugin):
    config_model = GroupRequestHandlerConfig

    _runner: Optional[web.AppRunner] = None
    _site: Optional[web.BaseSite] = None
    _pending: Dict[str, Dict[str, Any]] = {}
    _notified_flags: set = set()
    _silent_groups: Dict[str, Dict[str, Any]] = {}
    _send_exempt: Dict[str, Dict[str, float]] = {}
    _recently_notified: Dict[str, float] = {}  # group_id → expire_at，防重复推送
    _data_path: str = ""
    _whitelist_task: Optional[asyncio.Task] = None

    _ADMIN_COMMAND_PREFIXES = (
        "/审核通过", "/审核拒绝", "/群管理", "/群列表", "/群信息",
        "/退群", "/白名单", "/加白", "/删白", "/同意", "/拒绝",
    )

    # ── 生命周期 ──────────────────────────────────────────

    async def on_load(self) -> None:
        self._runner = None
        self._site = None
        self._pending = {}
        self._notified_flags = set()
        self._silent_groups = {}
        self._send_exempt = {}
        self._recently_notified = {}

        data_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(data_dir, exist_ok=True)
        self._data_path = os.path.join(data_dir, "state.json")
        self._load_state()

        if self.config.plugin.enabled:
            await self._start_webhook()
            self._start_whitelist_check()
        self.ctx.logger.info("群聊申请处理插件已加载")

    async def on_unload(self) -> None:
        await self._stop_webhook()
        self._stop_whitelist_check()
        self._save_state()

    async def on_config_update(self, scope: str, config_data: Dict[str, Any], version: str) -> None:
        if scope != CONFIG_RELOAD_SCOPE_SELF:
            return
        del config_data, version
        self._stop_whitelist_check()
        await self._stop_webhook()
        if self.config.plugin.enabled:
            await self._start_webhook()
            self._start_whitelist_check()

    # ── 消息静默（HookHandler 方案，同 group_muter_plugin）──

    @HookHandler(
        "chat.receive.after_process",
        name="silent_group_inbound_guard",
        description="审核中的群：入站拦截消息",
        mode=HookMode.BLOCKING,
        order=HookOrder.EARLY,
        timeout_ms=3000,
        error_policy=ErrorPolicy.SKIP,
    )
    async def _guard_silent_group_inbound(self, message: Optional[dict] = None, **kwargs: Any) -> Any:
        if not self._silent_groups:
            return None
        gid = self._extract_group_id_from_message(message)
        if not (gid and gid in self._silent_groups):
            return None
        if self._is_admin_command(message):
            return None
        self.ctx.logger.info(f"静默群 {gid} 入站消息已拦截")
        return {"action": "abort"}

    @HookHandler(
        "send_service.before_send",
        name="silent_group_outbound_guard",
        description="审核中的群：出站拦截消息",
        mode=HookMode.BLOCKING,
        order=HookOrder.EARLY,
        timeout_ms=3000,
        error_policy=ErrorPolicy.SKIP,
    )
    async def _guard_silent_group_outbound(self, message: Optional[dict] = None, **kwargs: Any) -> Any:
        if not self._silent_groups:
            return None
        gid = self._extract_group_id_from_message(message)
        if not gid and message:
            sid = str(message.get("session_id") or "")
            for part in sid.split(":"):
                if part.isdigit() and len(part) >= 5 and part in self._silent_groups:
                    gid = part
                    break
        if not (gid and gid in self._silent_groups):
            return None
        text = str(message.get("processed_plain_text") or "").strip()
        if self._consume_exempt(gid, text):
            return None
        self.ctx.logger.info(f"静默群 {gid} 出站消息已拦截")
        return {"action": "abort"}

    @staticmethod
    def _extract_group_id_from_message(message: Optional[dict]) -> str:
        if not isinstance(message, dict):
            return ""
        msg_info = message.get("message_info") or {}
        group_info = (msg_info.get("group_info") or {}) if isinstance(msg_info, dict) else {}
        gid = str(group_info.get("group_id") or "")
        if gid:
            return gid
        additional = (msg_info.get("additional_config") or {}) if isinstance(msg_info, dict) else {}
        return str(additional.get("platform_io_target_group_id") or "")

    def _is_admin_command(self, message: Optional[dict]) -> bool:
        if not isinstance(message, dict):
            return False
        text = str(message.get("processed_plain_text") or "").strip()
        if not text:
            return False
        msg_info = message.get("message_info") or {}
        user_info = msg_info.get("user_info") if isinstance(msg_info, dict) else {}
        uid = str(user_info.get("user_id") or "")
        if uid not in self._normalized_admin_qqs():
            return False
        return any(text.startswith(p) for p in self._ADMIN_COMMAND_PREFIXES)

    def _set_exempt(self, group_id: str, text: str, seconds: float = 10.0) -> None:
        if not group_id or not text:
            return
        tokens = self._send_exempt.setdefault(group_id, {})
        tokens[text.strip()] = time.time() + seconds

    def _consume_exempt(self, group_id: str, text: str) -> bool:
        tokens = self._send_exempt.get(group_id)
        if not tokens:
            return False
        now = time.time()
        for t in list(tokens):
            if now >= tokens[t]:
                del tokens[t]
        key = (text or "").strip()
        if key and key in tokens:
            del tokens[key]
            if not tokens:
                self._send_exempt.pop(group_id, None)
            return True
        return False

    # ── Webhook 服务 ───────────────────────────────────────

    async def _start_webhook(self) -> None:
        wh = self.config.webhook
        path = wh.path if wh.path.startswith("/") else f"/{wh.path}"
        app = web.Application()
        app.router.add_post(path, self._handle_webhook)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        try:
            self._site = web.TCPSite(self._runner, wh.host, int(wh.port))
            await self._site.start()
        except OSError as exc:
            self.ctx.logger.error(f"群聊申请 webhook 监听失败 {wh.host}:{wh.port}: {exc}")
            await self._stop_webhook()
            return
        self.ctx.logger.info(f"群聊申请 webhook 已监听: http://{wh.host}:{wh.port}{path}")

    async def _stop_webhook(self) -> None:
        site, runner = self._site, self._runner
        self._site = self._runner = None
        try:
            if site is not None:
                await site.stop()
        except Exception as exc:
            self.ctx.logger.warning(f"停止 webhook 监听失败: {exc}")
        try:
            if runner is not None:
                await runner.cleanup()
        except Exception as exc:
            self.ctx.logger.warning(f"清理 webhook 资源失败: {exc}")

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        raw = await request.read()
        if not self._verify_signature(request, raw):
            return web.Response(status=401, text="invalid signature")
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return web.Response(status=400, text="invalid json")
        if not isinstance(payload, dict):
            return web.Response(status=400, text="invalid payload")
        post_type = str(payload.get("post_type") or "").strip()
        request_type = str(payload.get("request_type") or "").strip()
        if post_type == "request" and request_type == "group":
            asyncio.create_task(self._on_group_request(payload))
        return web.json_response({})

    def _verify_signature(self, request: web.Request, raw: bytes) -> bool:
        secret = (self.config.webhook.secret or "").strip()
        if not secret:
            return True
        signature = request.headers.get("X-Signature", "")
        if not signature.startswith("sha1="):
            return False
        expected = "sha1=" + hmac.new(secret.encode("utf-8"), raw, sha1).hexdigest()
        return hmac.compare_digest(signature, expected)

    # ── 群邀请处理 ─────────────────────────────────────────

    async def _on_group_request(self, payload: Dict[str, Any]) -> None:
        try:
            sub_type = str(payload.get("sub_type") or "").strip()
            group_id = str(payload.get("group_id") or "").strip()
            flag = str(payload.get("flag") or "").strip()
            user_id = str(payload.get("user_id") or "").strip()
            comment = str(payload.get("comment") or "").strip()
            group_name = str(payload.get("group_name") or "").strip()
            if sub_type != "invite" or not group_id or not flag:
                return
            if flag in self._notified_flags:
                return
            self._notified_flags.add(flag)
            self._pending[group_id] = {
                "flag": flag, "user_id": user_id,
                "comment": comment, "group_name": group_name,
            }
            await self._notify_admins(group_id, user_id, group_name, comment)
            self._save_state()
        except Exception as exc:
            self.ctx.logger.warning(f"处理群邀请失败: {exc}")

    async def _notify_admins(self, group_id: str, user_id: str, group_name: str, comment: str) -> None:
        admin_qqs = self._normalized_admin_qqs()
        if not admin_qqs:
            self.ctx.logger.warning("收到群邀请但未配置管理员 QQ，无法推送")
            return
        lines = [
            "📨 新的群聊邀请",
            f"群号：{group_id}", f"群名：{group_name or '未知'}",
            f"邀请人：{user_id}",
        ]
        if comment:
            lines.append(f"验证消息：{comment}")
        lines.extend(["", f"回复 /同意 {group_id} 通过，/拒绝 {group_id} 拒绝"])
        text = "\n".join(lines)
        for admin_qq in admin_qqs:
            await self._send_private_text(admin_qq, text)
        self.ctx.logger.info(f"已推送群邀请: group_id={group_id} 邀请人={user_id}")

    # ── 白名单巡检 ─────────────────────────────────────────

    def _start_whitelist_check(self) -> None:
        if self._whitelist_task is None:
            self._whitelist_task = asyncio.create_task(self._whitelist_loop())

    def _stop_whitelist_check(self) -> None:
        if self._whitelist_task:
            self._whitelist_task.cancel()
            self._whitelist_task = None

    async def _whitelist_loop(self) -> None:
        interval = max(10, int(self.config.whitelist.check_interval_seconds))
        await asyncio.sleep(5)
        while True:
            try:
                if self.config.whitelist.enforce_whitelist:
                    await self._enforce_whitelist()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.ctx.logger.warning(f"白名单巡检出错: {exc}")
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break

    async def _enforce_whitelist(self) -> None:
        whitelist = self._normalized_whitelist()
        if not whitelist:
            return
        # 清理过期通知记录
        now = time.time()
        for gid in list(self._recently_notified):
            if now - self._recently_notified[gid] > 1200:
                del self._recently_notified[gid]
        groups = await self._get_group_list()
        if not groups:
            return
        current_gids = {str(g.get("group_id", "")).strip() for g in groups if str(g.get("group_id", "")).strip()}
        for gid in list(self._silent_groups.keys()):
            if gid not in current_gids:
                self.ctx.logger.info(f"审核中群 {gid} 已不在群列表，清理静默状态")
                self._silent_groups.pop(gid, None)
                self._save_state()
        for g in groups:
            gid = str(g.get("group_id", "")).strip()
            if not gid or gid in whitelist:
                continue
            if gid in self._silent_groups:
                continue
            gname = str(g.get("group_name", "未知"))
            self._silent_groups[gid] = {
                "added_at": time.time(), "group_name": gname,
                "member_count": g.get("member_count", "?"),
                "max_member_count": g.get("max_member_count", "?"),
            }
            self._save_state()
            self.ctx.logger.info(f"非白名单群 {gid}({gname}) 已加入审核队列，消息已静默")
            await self._notify_admins_review(gid, gname, g)
            await asyncio.sleep(1)

    async def _notify_admins_review(self, group_id: str, gname: str, group_data: Dict[str, Any]) -> None:
        admin_qqs = self._normalized_admin_qqs()
        if not admin_qqs:
            return
        # 防重复推送：10分钟内同一群不再推送
        now = time.time()
        last = self._recently_notified.get(group_id, 0)
        if now - last < 600:
            self.ctx.logger.info(f"群 {group_id} 审核通知在冷却期内，跳过推送")
            return
        self._recently_notified[group_id] = now
        member = group_data.get("member_count", "?")
        max_member = group_data.get("max_member_count", "?")
        text = "\n".join([
            "🔍 新群审核通知",
            f"群号：{group_id}", f"群名：{gname or '未知'}",
            f"人数：{member}/{max_member}",
            "",
            "该群不在白名单中，bot 已自动进入静默模式（不发送任何消息）。",
            "",
            f"/审核通过 {group_id} — 通过审核，bot 恢复正常发言",
            f"/审核拒绝 {group_id} — 拒绝审核，bot 退出该群",
        ])
        for admin_qq in admin_qqs:
            await self._send_private_text(admin_qq, text)
        self.ctx.logger.info(f"已推送群审核通知: group_id={group_id}")

    # ── 命令 ──────────────────────────────────────────────

    @Command("group_help", description="群聊管理帮助", pattern=r"^/群管理\s*$")
    async def handle_help(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        await self._reply(stream_id,
            "群聊管理指令：\n"
            "1. /群列表 — 查看所有群\n2. /群信息 <群号> — 查看群详情\n"
            "3. /退群 <群号> — 退出指定群\n4. /白名单 — 查看白名单\n"
            "5. /加白 <群号> — 添加白名单\n6. /删白 <群号> — 移除白名单\n"
            "7. /同意 <群号> — 通过群邀请\n8. /拒绝 <群号> — 拒绝群邀请\n"
            "9. /审核通过 <群号> — 通过群审核\n10. /审核拒绝 <群号> — 拒绝群审核并退群\n"
            "11. /群管理 — 本帮助"
        )
        return True, "帮助已发送", True

    @Command("group_list", description="查看 bot 加入的群列表", pattern=r"^/群列表\s*$")
    async def handle_group_list(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        groups = await self._get_group_list()
        if not groups:
            await self._reply(stream_id, "当前未加入任何群聊，或获取群列表失败。")
            return True, None, True
        wl = self._normalized_whitelist()
        silent = set(self._silent_groups.keys())
        lines = [f"📋 Bot 群列表（共 {len(groups)} 个）", ""]
        for i, g in enumerate(groups, 1):
            gid = str(g.get("group_id", "?"))
            gname = str(g.get("group_name", "未知"))
            max_member = g.get("max_member_count", "?")
            member = g.get("member_count", "?")
            if gid in wl:
                tag = "✅"
            elif gid in silent:
                tag = "🔍审核中"
            else:
                tag = "⬜"
            lines.append(f"{tag} {i}. {gname}")
            lines.append(f"   群号：{gid} | 人数：{member}/{max_member}")
        await self._reply(stream_id, "\n".join(lines))
        return True, "群列表已发送", True

    @Command("group_info", description="查看群详细信息", pattern=r"^/群信息\s+(?P<target_qq>\d+)\s*$")
    async def handle_group_info(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/群信息 <群号>")
            return True, None, True
        try:
            resp = await self._call_napcat("get_group_info", {"group_id": int(group_id)}, raise_on_error=False)
            data = resp.get("data", {}) if isinstance(resp, dict) else {}
            if not data:
                await self._reply(stream_id, f"未获取到群 {group_id} 的信息。")
                return True, None, True
            wl_status = "是" if group_id in self._normalized_whitelist() else "否"
            silent_status = "是（审核中）" if group_id in self._silent_groups else "否"
            lines = [
                f"📌 群信息",
                f"群号：{data.get('group_id', group_id)}",
                f"群名：{data.get('group_name', '未知')}",
                f"人数：{data.get('member_count', '?')}/{data.get('max_member_count', '?')}",
                f"群主：{data.get('owner_id', '未知')}",
                f"群介绍：{data.get('group_memo', '无')}",
                f"在白名单：{wl_status}",
                f"消息静默：{silent_status}",
            ]
            await self._reply(stream_id, "\n".join(lines))
        except Exception as exc:
            await self._reply(stream_id, f"获取群信息失败：{exc}")
        return True, None, True

    @Command("leave_group", description="退出指定群", pattern=r"^/退群\s+(?P<target_qq>\d+)\s*$")
    async def handle_leave(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/退群 <群号>")
            return True, None, True
        self._silent_groups.pop(group_id, None)
        ok = await self._leave_group(group_id, reason=f"管理员 {self._extract_sender_qq(kwargs)} 手动退群")
        if ok:
            await self._reply(stream_id, f"已退出群 {group_id}。")
        else:
            await self._reply(stream_id, f"退群 {group_id} 失败，请检查群号或稍后重试。")
        return True, None, True

    @Command("approve_group", description="管理员同意群邀请", pattern=r"^/同意\s+(?P<target_qq>\d+)\s*$")
    async def handle_approve(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        return await self._handle_group_decision(True, stream_id, **kwargs)

    @Command("reject_group", description="管理员拒绝群邀请", pattern=r"^/拒绝\s+(?P<target_qq>\d+)\s*$")
    async def handle_reject(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        return await self._handle_group_decision(False, stream_id, **kwargs)

    async def _handle_group_decision(self, approve: bool, stream_id: str, **kwargs: Any) -> tuple:
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/同意 <群号> 或 /拒绝 <群号>")
            return True, None, True
        record = self._pending.get(group_id)
        if record is None:
            await self._reply(stream_id, f"未找到群 {group_id} 的邀请记录，可能已过期或 webhook 未收到。")
            return True, None, True
        flag = record.get("flag", "")
        try:
            await self._call_napcat("set_group_add_request", {"flag": flag, "sub_type": "invite", "approve": bool(approve)}, raise_on_error=True)
        except Exception as exc:
            await self._reply(stream_id, f"处理失败：{exc}")
            return False, None, True
        self._pending.pop(group_id, None)
        self._notified_flags.discard(flag)
        self._save_state()
        if approve:
            await self._reply(stream_id, f"已通过群 {group_id} 的邀请。")
        else:
            if self.config.whitelist.leave_on_invite_reject:
                await self._leave_group(group_id, reason="管理员拒绝邀请后自动退群")
            await self._reply(stream_id, f"已拒绝群 {group_id} 的邀请。")
        return True, None, True

    @Command("review_approve", description="管理员审核通过新群", pattern=r"^/审核通过\s+(?P<target_qq>\d+)\s*$")
    async def handle_review_approve(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/审核通过 <群号>")
            return True, None, True
        if group_id not in self._silent_groups:
            await self._reply(stream_id, f"群 {group_id} 不在审核队列中。")
            return True, None, True
        # ⚠️ 先写 config（白名单），再动 state，防止 on_config_update 触发的巡检读不到新白名单
        wl = list(self.config.whitelist.group_whitelist) if isinstance(self.config.whitelist.group_whitelist, list) else []
        if group_id not in [str(x).strip() for x in wl]:
            wl.append(group_id)
            self.config.whitelist.group_whitelist = wl
            await self._save_config()
            self.ctx.logger.info(f"群审核通过，已加白名单: {group_id}")
        self._silent_groups.pop(group_id, None)
        self._recently_notified.pop(group_id, None)
        self._save_state()
        await self._reply(stream_id, f"✅ 已通过群 {group_id} 审核，bot 恢复正常发言，已加入白名单。")
        return True, None, True

    @Command("review_reject", description="管理员审核拒绝新群并退群", pattern=r"^/审核拒绝\s+(?P<target_qq>\d+)\s*$")
    async def handle_review_reject(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/审核拒绝 <群号>")
            return True, None, True
        if group_id not in self._silent_groups:
            await self._reply(stream_id, f"群 {group_id} 不在审核队列中。")
            return True, None, True
        self._silent_groups.pop(group_id, None)
        self._save_state()
        ok = await self._leave_group(group_id, reason="管理员审核拒绝")
        if ok:
            await self._reply(stream_id, f"✅ 已拒绝群 {group_id} 并退出。")
        else:
            await self._reply(stream_id, f"审核已拒绝但退群失败: {group_id}")
        return True, None, True

    @Command("wl_show", description="查看白名单", pattern=r"^/白名单\s*$")
    async def handle_wl_show(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        wl = self._normalized_whitelist()
        if not wl:
            await self._reply(stream_id, "白名单为空，不限制群聊。")
        else:
            lines = [f"📋 白名单（共 {len(wl)} 个群）", ""]
            for i, gid in enumerate(wl, 1):
                gname = await self._group_name(gid)
                lines.append(f"{i}. {gname} ({gid})")
            await self._reply(stream_id, "\n".join(lines))
        return True, None, True

    @Command("wl_add", description="添加群到白名单", pattern=r"^/加白\s+(?P<target_qq>\d+)\s*$")
    async def handle_wl_add(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/加白 <群号>")
            return True, None, True
        wl = list(self.config.whitelist.group_whitelist) if isinstance(self.config.whitelist.group_whitelist, list) else []
        if group_id in [str(x).strip() for x in wl]:
            await self._reply(stream_id, f"群 {group_id} 已在白名单中。")
            return True, None, True
        wl.append(group_id)
        self.config.whitelist.group_whitelist = wl
        await self._save_config()
        if group_id in self._silent_groups:
            self._silent_groups.pop(group_id, None)
            self._recently_notified.pop(group_id, None)
            self._save_state()
        await self._reply(stream_id, f"已将群 {group_id} 加入白名单。")
        return True, None, True

    @Command("wl_del", description="从白名单移除群", pattern=r"^/删白\s+(?P<target_qq>\d+)\s*$")
    async def handle_wl_del(self, stream_id: str = "", **kwargs: Any) -> tuple:
        if not self._is_admin(kwargs):
            return False, None, False
        matched = kwargs.get("matched_groups") or {}
        group_id = str(matched.get("target_qq", "")).strip()
        if not group_id:
            await self._reply(stream_id, "用法：/删白 <群号>")
            return True, None, True
        wl = list(self.config.whitelist.group_whitelist) if isinstance(self.config.whitelist.group_whitelist, list) else []
        removed = [x for x in wl if str(x).strip() != group_id]
        if len(removed) == len(wl):
            await self._reply(stream_id, f"群 {group_id} 不在白名单中。")
            return True, None, True
        self.config.whitelist.group_whitelist = removed
        await self._save_config()
        await self._reply(stream_id, f"已将群 {group_id} 移出白名单。")
        return True, None, True

    # ── 工具方法 ──────────────────────────────────────────

    def _normalized_admin_qqs(self) -> List[str]:
        return [str(qq).strip() for qq in self.config.admin.admin_qqs if str(qq).strip()]

    def _normalized_whitelist(self) -> List[str]:
        return [str(g).strip() for g in self.config.whitelist.group_whitelist if str(g).strip()]

    def _is_admin(self, kwargs: Dict[str, Any]) -> bool:
        sender = self._extract_sender_qq(kwargs)
        return sender is not None and sender in self._normalized_admin_qqs()

    @staticmethod
    def _extract_sender_qq(kwargs: Dict[str, Any]) -> Optional[str]:
        base_info = kwargs.get("message_base_info") or {}
        user_info = base_info.get("user_info") if isinstance(base_info, dict) else {}
        sender = kwargs.get("user_id") or (user_info.get("user_id") if isinstance(user_info, dict) else None)
        return str(sender).strip() if sender else None

    async def _reply(self, stream_id: str, text: str) -> None:
        if not stream_id or not text:
            return
        # 给静默群的命令回复发豁免令牌
        for gid in self._silent_groups:
            if gid in stream_id:
                self._set_exempt(gid, text, seconds=10.0)
                break
        try:
            await self.ctx.send.text(text, stream_id)
        except Exception as exc:
            self.ctx.logger.warning(f"回复消息失败: {exc}")

    async def _send_private_text(self, user_id: str, text: str) -> None:
        if not user_id or not text:
            return
        await self._call_napcat(
            "send_private_msg",
            {"user_id": int(user_id), "message": [{"type": "text", "data": {"text": text}}]},
            raise_on_error=False,
        )

    async def _call_napcat(self, action_name: str, params: Dict[str, Any], raise_on_error: bool = False) -> Any:
        try:
            response = await self.ctx.api.call("adapter.napcat.action.call", action_name=action_name, params=params)
        except Exception as exc:
            if raise_on_error:
                raise
            self.ctx.logger.debug(f"调用 NapCat {action_name} 失败: {exc}")
            return None
        if isinstance(response, dict) and str(response.get("status", "")).lower() not in {"", "ok"}:
            msg = str(response.get("wording") or response.get("message") or response.get("retcode"))
            if raise_on_error:
                raise RuntimeError(f"NapCat {action_name} 错误: {msg}")
            self.ctx.logger.debug(f"NapCat {action_name} 非 ok: {msg}")
        return response

    async def _get_group_list(self) -> List[Dict[str, Any]]:
        try:
            resp = await self._call_napcat("get_group_list", {}, raise_on_error=False)
            if isinstance(resp, dict):
                data = resp.get("data", [])
                if isinstance(data, list):
                    return data
        except Exception as exc:
            self.ctx.logger.warning(f"获取群列表失败: {exc}")
        return []

    async def _leave_group(self, group_id: str, reason: str = "") -> bool:
        gname = await self._group_name(group_id)
        try:
            resp = await self._call_napcat("set_group_leave", {"group_id": int(group_id)}, raise_on_error=False)
            self.ctx.logger.info(f"退出群 {group_id}({gname}) 结果: {resp}")
            await self._notify_admins_leave(group_id, gname, reason, success=True)
            return True
        except Exception as exc:
            self.ctx.logger.warning(f"退出群 {group_id}({gname}) 失败: {exc}")
            await self._notify_admins_leave(group_id, gname, reason, success=False, error=str(exc))
            return False

    async def _notify_admins_leave(self, group_id: str, gname: str, reason: str, success: bool, error: str = "") -> None:
        admin_qqs = self._normalized_admin_qqs()
        if not admin_qqs:
            return
        status = "✅ 已退出群聊" if success else "❌ 退群失败"
        lines = [f"{status}", f"群号：{group_id}", f"群名：{gname or group_id}"]
        if reason:
            lines.append(f"原因：{reason}")
        if error:
            lines.append(f"错误：{error}")
        text = "\n".join(lines)
        for admin_qq in admin_qqs:
            await self._send_private_text(admin_qq, text)
        self.ctx.logger.info(f"已推送退群通知: group_id={group_id} success={success}")

    async def _group_name(self, group_id: str) -> str:
        try:
            resp = await self._call_napcat("get_group_info", {"group_id": int(group_id)}, raise_on_error=False)
            if isinstance(resp, dict):
                data = resp.get("data", {})
                if isinstance(data, dict):
                    return str(data.get("group_name", group_id))
        except Exception:
            pass
        return group_id

    async def _save_config(self) -> None:
        try:
            await self.ctx.save_config()
            self.ctx.logger.info("配置已保存")
        except Exception as exc:
            self.ctx.logger.error(f"保存配置失败: {exc}", exc_info=True)

    # ── 持久化 ────────────────────────────────────────────

    def _load_state(self) -> None:
        try:
            with open(self._data_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            pending = payload.get("pending")
            if isinstance(pending, dict):
                self._pending = {str(k): dict(v) for k, v in pending.items() if isinstance(v, dict)}
            notified = payload.get("notified_flags")
            if isinstance(notified, list):
                self._notified_flags = {str(i) for i in notified}
            silent = payload.get("silent_groups")
            if isinstance(silent, dict):
                self._silent_groups = {str(k): dict(v) for k, v in silent.items() if isinstance(v, dict)}
            recent = payload.get("recently_notified")
            if isinstance(recent, dict):
                now = time.time()
                self._recently_notified = {
                    str(k): float(v) for k, v in recent.items()
                    if isinstance(v, (int, float)) and float(v) > now - 1200
                }
        except FileNotFoundError:
            return
        except Exception as exc:
            self.ctx.logger.warning(f"读取状态失败: {exc}")

    def _save_state(self) -> None:
        try:
            with open(self._data_path, "w", encoding="utf-8") as f:
                json.dump({
                    "pending": self._pending,
                    "notified_flags": sorted(self._notified_flags),
                    "silent_groups": self._silent_groups,
                    "recently_notified": self._recently_notified,
                }, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            self.ctx.logger.warning(f"保存状态失败: {exc}")


def create_plugin() -> GroupRequestHandlerPlugin:
    return GroupRequestHandlerPlugin()
