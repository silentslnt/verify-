"""Discord bot — slash commands for panel management."""
from __future__ import annotations

import asyncio
import logging
import os

import discord
from discord import app_commands

OWNER_ID = int(os.getenv("OWNER_ID", "0")) or None
DEFAULT_VERIFY_URL = os.getenv("VERIFY_URL", "")

log = logging.getLogger("verifybot.bot")

DEFAULT_PANEL_MSG = (
    "To gain access to **{guild}** you need to prove you are a human "
    "by completing verification.\n"
    "Click the button below to get started!\n\n"
    "__**Incase loss of access happens you will be brought into the new server**__"
)


class WhyButton(discord.ui.DynamicItem[discord.ui.Button],
                template=r"vb:why:(?P<guild_id>\d+)"):
    def __init__(self, guild_id: int):
        super().__init__(
            discord.ui.Button(
                style=discord.ButtonStyle.secondary,
                label="Why?",
                custom_id=f"vb:why:{guild_id}",
            )
        )

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(int(match["guild_id"]))

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.send_message(
            "This server uses verification to keep bots and alt accounts out. "
            "Completing it proves you're a real person and grants you access.",
            ephemeral=True,
        )


class VerifyBot(discord.Client):
    def __init__(self, pool):
        intents = discord.Intents.default()
        intents.members = True
        super().__init__(intents=intents, owner_id=OWNER_ID)
        self.tree = app_commands.CommandTree(self)
        self.db = pool

    async def setup_hook(self):
        self.add_dynamic_items(WhyButton)
        _register_commands(self)
        await self.tree.sync()
        log.info("Slash commands synced.")

    async def on_ready(self):
        log.info("Logged in as %s (%s) | %d guilds", self.user, self.user.id, len(self.guilds))

    async def on_member_join(self, member: discord.Member):
        row = await self.db.fetchrow(
            "SELECT unverified_role_id FROM verify_config WHERE guild_id=$1", member.guild.id
        )
        if not row or not row["unverified_role_id"]:
            return
        role = member.guild.get_role(row["unverified_role_id"])
        if role:
            try:
                await member.add_roles(role, reason="verify gate")
            except discord.HTTPException:
                pass


def make_bot(pool) -> VerifyBot:
    return VerifyBot(pool)


def _is_admin(interaction: discord.Interaction) -> bool:
    if OWNER_ID and interaction.user.id == OWNER_ID:
        return True
    return (
        interaction.user.id == interaction.guild.owner_id
        or interaction.user.guild_permissions.administrator
    )


async def _cfg(bot: VerifyBot, guild_id: int) -> dict | None:
    row = await bot.db.fetchrow("SELECT * FROM verify_config WHERE guild_id=$1", guild_id)
    return dict(row) if row else None


async def _upsert(bot: VerifyBot, guild_id: int, **fields):
    await bot.db.execute(
        "INSERT INTO verify_config (guild_id) VALUES ($1) ON CONFLICT DO NOTHING", guild_id,
    )
    if fields:
        sets = ", ".join(f"{k}=${i+2}" for i, k in enumerate(fields))
        await bot.db.execute(
            f"UPDATE verify_config SET {sets} WHERE guild_id=$1",
            guild_id, *fields.values(),
        )


def _build_panel(guild: discord.Guild, cfg: dict | None, verify_url: str) -> tuple[discord.Embed, discord.ui.View]:
    image_url = (cfg or {}).get("image_url")
    msg = (cfg or {}).get("panel_msg") or DEFAULT_PANEL_MSG.format(guild=guild.name)

    embed = discord.Embed(title="⭐ Verification required", description=msg, color=0x000000)
    if image_url:
        embed.set_image(url=image_url)

    # Append guild_id so the OAuth2 callback knows which server triggered the verify
    url_with_guild = f"{verify_url}?guild={guild.id}" if "?" not in verify_url else f"{verify_url}&guild={guild.id}"

    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(style=discord.ButtonStyle.link, label="Verify now", url=url_with_guild))
    view.add_item(WhyButton(guild.id))
    return embed, view


def _register_commands(bot: VerifyBot):
    verify_group = app_commands.Group(name="verify", description="Verification panel", guild_only=True)

    @verify_group.command(name="panel", description="Post the verification panel")
    @app_commands.describe(channel="Channel to post in (defaults to current)")
    async def slash_panel(interaction: discord.Interaction, channel: discord.TextChannel = None):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        channel = channel or interaction.channel
        cfg = await _cfg(bot, interaction.guild_id)
        verify_url = (cfg or {}).get("verify_url") or DEFAULT_VERIFY_URL
        if not verify_url:
            return await interaction.response.send_message(
                "❌ Set a verify URL first with `/verify url`.", ephemeral=True,
            )
        embed, view = _build_panel(interaction.guild, cfg, verify_url)
        try:
            await channel.send(embed=embed, view=view)
        except discord.Forbidden:
            return await interaction.response.send_message(
                f"❌ Missing permissions in {channel.mention}.", ephemeral=True,
            )
        await interaction.response.send_message(f"✅ Panel posted in {channel.mention}.", ephemeral=True)

    @verify_group.command(name="image", description="Set the panel image for this server")
    @app_commands.describe(url="Direct image URL")
    async def slash_image(interaction: discord.Interaction, url: str):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        if not url.startswith("http"):
            return await interaction.response.send_message("❌ Must be a valid URL.", ephemeral=True)
        await _upsert(bot, interaction.guild_id, image_url=url)
        embed = discord.Embed(description="✅ Panel image updated.", color=0x000000)
        embed.set_image(url=url)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @verify_group.command(name="url", description="Set the verification link for this server")
    @app_commands.describe(url="Your OAuth2 verify page URL")
    async def slash_url(interaction: discord.Interaction, url: str):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        if not url.startswith("http"):
            return await interaction.response.send_message("❌ Must be a valid URL.", ephemeral=True)
        await _upsert(bot, interaction.guild_id, verify_url=url)
        await interaction.response.send_message("✅ Verification URL set.", ephemeral=True)

    @verify_group.command(name="role", description="Role to grant after verification")
    @app_commands.describe(role="Role to assign on verify")
    async def slash_role(interaction: discord.Interaction, role: discord.Role):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        if role >= interaction.guild.me.top_role:
            return await interaction.response.send_message("❌ That role is above mine.", ephemeral=True)
        await _upsert(bot, interaction.guild_id, role_id=role.id)
        await interaction.response.send_message(f"✅ Verified role set to {role.mention}.", ephemeral=True)

    @verify_group.command(name="message", description="Set a custom panel description — shows a preview")
    @app_commands.describe(text="Custom embed description")
    async def slash_message(interaction: discord.Interaction, text: str):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        await _upsert(bot, interaction.guild_id, panel_msg=text)
        cfg = await _cfg(bot, interaction.guild_id)
        verify_url = cfg.get("verify_url") or DEFAULT_VERIFY_URL or "https://example.com"
        embed, view = _build_panel(interaction.guild, cfg, verify_url)
        await interaction.response.send_message(
            content="✅ Panel message updated. Preview:",
            embed=embed,
            view=view,
            ephemeral=True,
        )

    @verify_group.command(name="config", description="View this server's verify setup")
    async def slash_config(interaction: discord.Interaction):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        cfg = await _cfg(bot, interaction.guild_id)
        if not cfg:
            return await interaction.response.send_message("ℹ️ Not configured yet.", ephemeral=True)
        role = interaction.guild.get_role(cfg["role_id"]) if cfg.get("role_id") else None
        embed = discord.Embed(title="Verify config", color=0x000000)
        embed.add_field(name="Verify URL", value=cfg.get("verify_url") or "—", inline=False)
        embed.add_field(name="Image", value="Set" if cfg.get("image_url") else "—", inline=True)
        embed.add_field(name="Role", value=role.mention if role else "—", inline=True)
        if cfg.get("image_url"):
            embed.set_thumbnail(url=cfg["image_url"])
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @verify_group.command(name="setup", description="Create Verified/Unverified roles and lock all channels automatically")
    @app_commands.describe(channel="Existing channel to use as the verify channel (creates #verify if not set)")
    async def slash_setup(interaction: discord.Interaction, channel: discord.TextChannel = None):
        if not _is_admin(interaction):
            return await interaction.response.send_message("❌ Administrators only.", ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        lines: list[str] = []

        # Verified role
        verified_role = discord.utils.get(guild.roles, name="Verified")
        if not verified_role:
            verified_role = await guild.create_role(name="Verified", color=discord.Color.green(), reason="verifysetup")
            lines.append("✅ Created **Verified** role")
        else:
            lines.append("— Found existing **Verified** role")

        # Unverified role
        unverified_role = discord.utils.get(guild.roles, name="Unverified")
        if not unverified_role:
            unverified_role = await guild.create_role(name="Unverified", color=discord.Color.light_grey(), reason="verifysetup")
            lines.append("✅ Created **Unverified** role")
        else:
            lines.append("— Found existing **Unverified** role")

        # Verify channel
        verify_ch = channel or discord.utils.get(guild.text_channels, name="verify")
        if not verify_ch:
            verify_ch = await guild.create_text_channel("verify", reason="verifysetup")
            lines.append("✅ Created **#verify** channel")
        else:
            lines.append(f"— Using {verify_ch.mention} as verify channel")

        # Lock all channels from Unverified
        locked = failed = 0
        for cat in guild.categories:
            try:
                await cat.set_permissions(unverified_role, view_channel=False)
                locked += 1
            except discord.HTTPException:
                failed += 1
            await asyncio.sleep(0.2)

        for ch in guild.channels:
            if ch.category is None and not isinstance(ch, discord.CategoryChannel) and ch.id != verify_ch.id:
                try:
                    await ch.set_permissions(unverified_role, view_channel=False)
                    locked += 1
                except discord.HTTPException:
                    failed += 1
                await asyncio.sleep(0.2)

        # Allow Unverified to see only the verify channel (read-only)
        await verify_ch.set_permissions(unverified_role, view_channel=True, send_messages=False, read_message_history=True)
        suffix = f" ({failed} failed — missing permissions)" if failed else ""
        lines.append(f"✅ Locked {locked} categories/channels for **Unverified**{suffix}")

        # Save config
        await _upsert(bot, guild.id,
                      role_id=verified_role.id,
                      unverified_role_id=unverified_role.id,
                      verify_channel_id=verify_ch.id)
        lines.append("✅ Config saved")

        # Post panel if URL is set
        cfg = await _cfg(bot, guild.id)
        verify_url = (cfg or {}).get("verify_url") or DEFAULT_VERIFY_URL
        if verify_url:
            embed, view = _build_panel(guild, cfg, verify_url)
            await verify_ch.send(embed=embed, view=view)
            lines.append(f"✅ Panel posted in {verify_ch.mention}")
        else:
            lines.append(f"⚠️ No verify URL set — run `/verify url <url>` then `/verify panel` to post the panel")

        await interaction.followup.send("\n".join(lines), ephemeral=True)

    bot.tree.add_command(verify_group)
