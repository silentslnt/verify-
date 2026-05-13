"""HTTP server — OAuth2 callback + REST API for the admin panel."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from urllib.parse import urlencode

import aiohttp
from aiohttp import web

CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "changeme")
PORT = int(os.getenv("PORT", "8080"))

STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_GUILD_ID = int(os.getenv("STRIPE_GUILD_ID", "0")) or None
STRIPE_STANDARD_PRICE_ID = os.getenv("STRIPE_STANDARD_PRICE_ID", "")
STRIPE_STANDARD_ROLE_ID = int(os.getenv("STRIPE_STANDARD_ROLE_ID", "0")) or None
STRIPE_MENTORSHIP_PRICE_ID = os.getenv("STRIPE_MENTORSHIP_PRICE_ID", "")
STRIPE_MENTORSHIP_ROLE_ID = int(os.getenv("STRIPE_MENTORSHIP_ROLE_ID", "0")) or None
# Stripe payment link base URLs (buy.stripe.com/...)
STRIPE_STANDARD_LINK = os.getenv("STRIPE_STANDARD_LINK", "")
STRIPE_MENTORSHIP_LINK = os.getenv("STRIPE_MENTORSHIP_LINK", "")
STRIPE_STANDARD_PLINK_ID = os.getenv("STRIPE_STANDARD_PLINK_ID", "")
STRIPE_MENTORSHIP_PLINK_ID = os.getenv("STRIPE_MENTORSHIP_PLINK_ID", "")
# Separate redirect URI for the subscribe OAuth2 flow
SUBSCRIBE_REDIRECT_URI = os.getenv("SUBSCRIBE_REDIRECT_URI", "")

log = logging.getLogger("verifybot.api")

DISCORD_API = "https://discord.com/api/v10"


def _oauth2_url(state: str = "") -> str:
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds.join",
    }
    if state:
        params["state"] = state
    return "https://discord.com/oauth2/authorize?" + urlencode(params)


# ── Middleware ────────────────────────────────────────────────────────────────

@web.middleware
async def cors_middleware(request: web.Request, handler):
    if request.method == "OPTIONS":
        return web.Response(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        })
    resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def _check_auth(request: web.Request) -> bool:
    return request.headers.get("Authorization", "") == f"Bearer {ADMIN_SECRET}"


# ── Routes ────────────────────────────────────────────────────────────────────

async def handle_verify(request: web.Request) -> web.Response:
    """Redirect to Discord OAuth2, passing guild_id as state."""
    guild_id = request.rel_url.query.get("guild", "")
    raise web.HTTPFound(_oauth2_url(state=guild_id))


async def handle_callback(request: web.Request) -> web.Response:
    """Exchange OAuth2 code, store token + source guild."""
    code = request.rel_url.query.get("code")
    source_guild_id = request.rel_url.query.get("state") or None
    if not code:
        return web.Response(
            text=_page("❌ Auth failed", "No code received. Please try again.", "#ff4444"),
            content_type="text/html",
        )

    db = request.app["db"]

    async with aiohttp.ClientSession() as session:
        async with session.post(f"{DISCORD_API}/oauth2/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }) as r:
            if r.status != 200:
                return web.Response(
                    text=_page("❌ Auth failed", "Could not exchange token. Please try again.", "#ff4444"),
                    content_type="text/html",
                )
            token_data = await r.json()

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 604800)

        async with session.get(f"{DISCORD_API}/users/@me",
                               headers={"Authorization": f"Bearer {access_token}"}) as r:
            if r.status != 200:
                return web.Response(
                    text=_page("❌ Auth failed", "Could not fetch user info.", "#ff4444"),
                    content_type="text/html",
                )
            user = await r.json()

    user_id = int(user["id"])
    username = user.get("global_name") or user.get("username", "Unknown")
    avatar_hash = user.get("avatar")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png"
        if avatar_hash else
        f"https://cdn.discordapp.com/embed/avatars/{user_id % 5}.png"
    )

    source_guild_id_int = int(source_guild_id) if source_guild_id and source_guild_id.isdigit() else None

    await db.execute(
        """INSERT INTO verify_members
               (user_id, username, avatar, access_token, refresh_token, token_expires_at, source_guild_id)
           VALUES ($1, $2, $3, $4, $5, now() + $6 * interval '1 second', $7)
           ON CONFLICT (user_id) DO UPDATE
           SET username=EXCLUDED.username, avatar=EXCLUDED.avatar,
               access_token=EXCLUDED.access_token, refresh_token=EXCLUDED.refresh_token,
               token_expires_at=EXCLUDED.token_expires_at,
               source_guild_id=EXCLUDED.source_guild_id,
               verified_at=now()""",
        user_id, username, avatar_url, access_token, refresh_token, expires_in, source_guild_id_int,
    )

    log.info("Verified: %s (%s) from guild %s", username, user_id, source_guild_id_int)

    # Grant verified role / remove unverified role if the bot is in the source guild
    bot = request.app["bot"]
    if source_guild_id_int:
        guild = bot.get_guild(source_guild_id_int)
        if guild:
            member = guild.get_member(user_id)
            if member:
                cfg_row = await db.fetchrow(
                    "SELECT role_id, unverified_role_id FROM verify_config WHERE guild_id=$1",
                    source_guild_id_int,
                )
                if cfg_row:
                    try:
                        if cfg_row["role_id"]:
                            r = guild.get_role(cfg_row["role_id"])
                            if r:
                                await member.add_roles(r, reason="verified via OAuth2")
                        if cfg_row["unverified_role_id"]:
                            r = guild.get_role(cfg_row["unverified_role_id"])
                            if r and r in member.roles:
                                await member.remove_roles(r, reason="verified via OAuth2")
                    except Exception:
                        pass

    return web.Response(
        text=_page("✅ Verified!", f"Welcome, <b>{username}</b>. You're all set — you can close this window.", "#00c853"),
        content_type="text/html",
    )


async def handle_members(request: web.Request) -> web.Response:
    """GET /api/members — paginated member list."""
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)

    db = request.app["db"]
    bot = request.app["bot"]
    search = request.rel_url.query.get("q", "").strip()
    page = max(1, int(request.rel_url.query.get("page", 1)))
    per_page = 20
    offset = (page - 1) * per_page

    if search:
        rows = await db.fetch(
            """SELECT user_id, username, avatar, verified_at, source_guild_id,
                      (token_expires_at > now()) AS pullable
               FROM verify_members
               WHERE username ILIKE $1 OR user_id::text = $1
               ORDER BY verified_at DESC LIMIT $2 OFFSET $3""",
            f"%{search}%", per_page, offset,
        )
        total = await db.fetchval(
            "SELECT COUNT(*) FROM verify_members WHERE username ILIKE $1 OR user_id::text=$1",
            f"%{search}%",
        )
    else:
        rows = await db.fetch(
            """SELECT user_id, username, avatar, verified_at, source_guild_id,
                      (token_expires_at > now()) AS pullable
               FROM verify_members
               ORDER BY verified_at DESC LIMIT $1 OFFSET $2""",
            per_page, offset,
        )
        total = await db.fetchval("SELECT COUNT(*) FROM verify_members")

    pullable = await db.fetchval("SELECT COUNT(*) FROM verify_members WHERE token_expires_at > now()")
    deauth = await db.fetchval("SELECT COUNT(*) FROM verify_members WHERE token_expires_at <= now()")

    # Resolve source guild names from the bot's cache
    def guild_name(guild_id):
        if not guild_id:
            return None
        g = bot.get_guild(guild_id)
        return g.name if g else str(guild_id)

    members = [
        {
            "user_id": str(r["user_id"]),
            "username": r["username"],
            "avatar": r["avatar"],
            "verified_at": r["verified_at"].strftime("%Y-%m-%d") if r["verified_at"] else "—",
            "pullable": r["pullable"],
            "source_guild_id": str(r["source_guild_id"]) if r["source_guild_id"] else None,
            "source_guild_name": guild_name(r["source_guild_id"]),
        }
        for r in rows
    ]

    return web.json_response({
        "members": members,
        "total": total,
        "pullable": pullable,
        "deauthorized": deauth,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
    })


async def handle_servers(request: web.Request) -> web.Response:
    """GET /api/servers — list all servers the bot is in."""
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)

    bot = request.app["bot"]
    db = request.app["db"]

    servers = []
    for guild in bot.guilds:
        pullable = await db.fetchval(
            "SELECT COUNT(*) FROM verify_members WHERE source_guild_id=$1 AND token_expires_at > now()",
            guild.id,
        )
        total = await db.fetchval(
            "SELECT COUNT(*) FROM verify_members WHERE source_guild_id=$1",
            guild.id,
        )
        servers.append({
            "id": str(guild.id),
            "name": guild.name,
            "icon": str(guild.icon.url) if guild.icon else None,
            "members": guild.member_count,
            "pullable": pullable,
            "total_verified": total,
        })

    servers.sort(key=lambda s: s["total_verified"], reverse=True)
    return web.json_response({"servers": servers})


async def handle_pull(request: web.Request) -> web.Response:
    """POST /api/pull — add member(s) to a Discord server."""
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)

    body = await request.json()
    guild_id = body.get("guild_id")
    user_ids = body.get("user_ids", "all")

    if not guild_id:
        return web.json_response({"error": "guild_id required"}, status=400)

    db = request.app["db"]
    bot_token = os.getenv("DISCORD_TOKEN", "")

    limit = body.get("limit")  # optional: pull only first N pullable members

    if user_ids == "all":
        if limit:
            rows = await db.fetch(
                "SELECT user_id, access_token FROM verify_members WHERE token_expires_at > now() ORDER BY verified_at DESC LIMIT $1",
                int(limit),
            )
        else:
            rows = await db.fetch(
                "SELECT user_id, access_token FROM verify_members WHERE token_expires_at > now()"
            )
    else:
        ids = [int(uid) for uid in user_ids]
        rows = await db.fetch(
            "SELECT user_id, access_token FROM verify_members WHERE user_id = ANY($1) AND token_expires_at > now()",
            ids,
        )

    # Fetch verified role for this guild once
    bot = request.app["bot"]
    cfg_row = await db.fetchrow(
        "SELECT role_id, unverified_role_id FROM verify_config WHERE guild_id=$1", int(guild_id)
    )
    guild = bot.get_guild(int(guild_id))
    verified_role = guild.get_role(cfg_row["role_id"]) if cfg_row and cfg_row["role_id"] and guild else None
    unverified_role = guild.get_role(cfg_row["unverified_role_id"]) if cfg_row and cfg_row["unverified_role_id"] and guild else None

    pulled = failed = 0
    async with aiohttp.ClientSession() as session:
        for row in rows:
            async with session.put(
                f"{DISCORD_API}/guilds/{guild_id}/members/{row['user_id']}",
                headers={"Authorization": f"Bot {bot_token}", "Content-Type": "application/json"},
                data=json.dumps({"access_token": row["access_token"]}),
            ) as r:
                if r.status in (200, 201, 204):
                    pulled += 1
                    # Grant verified role + remove unverified role after successful pull
                    if guild and (verified_role or unverified_role):
                        try:
                            member = guild.get_member(row["user_id"]) or await guild.fetch_member(row["user_id"])
                            if verified_role and verified_role not in member.roles:
                                await member.add_roles(verified_role, reason="pulled via admin panel")
                            if unverified_role and unverified_role in member.roles:
                                await member.remove_roles(unverified_role, reason="pulled via admin panel")
                        except Exception:
                            pass
                else:
                    failed += 1
                    log.warning("Pull failed for %s: %s", row["user_id"], r.status)

    return web.json_response({"pulled": pulled, "failed": failed})


async def handle_delete_member(request: web.Request) -> web.Response:
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)
    user_id = int(request.match_info["user_id"])
    await request.app["db"].execute("DELETE FROM verify_members WHERE user_id=$1", user_id)
    return web.json_response({"ok": True})


async def handle_delete_deauth(request: web.Request) -> web.Response:
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)
    result = await request.app["db"].execute(
        "DELETE FROM verify_members WHERE token_expires_at <= now()"
    )
    n = int(result.split()[-1]) if result.startswith("DELETE") else 0
    return web.json_response({"deleted": n})


# ── Subscribe flow (Discord OAuth2 → Stripe) ─────────────────────────────────

def _subscribe_oauth2_url(tier: str) -> str:
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": SUBSCRIBE_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": tier,
    }
    return "https://discord.com/oauth2/authorize?" + urlencode(params)


async def handle_subscribe(request: web.Request) -> web.Response:
    """Show branded landing page before Discord OAuth2."""
    tier = request.rel_url.query.get("tier", "")
    if tier not in ("standard", "mentorship"):
        return web.Response(
            text=_page("❌ Invalid tier", "Unknown subscription tier.", "#ff4444"),
            content_type="text/html",
        )
    if not SUBSCRIBE_REDIRECT_URI:
        return web.Response(
            text=_page("❌ Not configured", "Subscribe redirect URI not set.", "#ff4444"),
            content_type="text/html",
        )

    tier_label = "Standard Access — $50/mo" if tier == "standard" else "Mentorship — $300/mo"
    tier_desc = (
        "Full server access — all signals, education, and community channels."
        if tier == "standard" else
        "Everything in Standard + private 1-on-1 sessions, exclusive setups, and direct mentor access."
    )
    oauth_url = _subscribe_oauth2_url(tier)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>P.E.A.K Trades — Subscribe</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#050208;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#fff}}
.wrap{{text-align:center;padding:56px 40px;max-width:480px;width:100%}}
.logo{{font-size:13px;font-weight:700;letter-spacing:4px;color:rgba(255,255,255,.3);text-transform:uppercase;margin-bottom:40px}}
.card{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:36px 32px;margin-bottom:28px}}
.tier{{font-size:11px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:rgba(255,255,255,.35);margin-bottom:10px}}
.price{{font-size:26px;font-weight:800;color:#fff;margin-bottom:12px}}
.desc{{font-size:14px;color:rgba(255,255,255,.5);line-height:1.6}}
.divider{{height:1px;background:rgba(255,255,255,.06);margin:24px 0}}
.note{{font-size:12px;color:rgba(255,255,255,.3);line-height:1.7;margin-bottom:28px}}
.note b{{color:rgba(255,255,255,.55)}}
.btn{{display:inline-flex;align-items:center;gap:10px;background:#5865f2;color:#fff;font-size:15px;font-weight:700;padding:14px 32px;border-radius:10px;text-decoration:none;transition:opacity .2s;width:100%;justify-content:center}}
.btn:hover{{opacity:.85}}
.btn svg{{width:20px;height:20px;fill:#fff;flex-shrink:0}}
.sub{{font-size:11px;color:rgba(255,255,255,.2);margin-top:18px;line-height:1.6}}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">P.E.A.K Trades</div>
  <div class="card">
    <div class="tier">Selected Plan</div>
    <div class="price">{tier_label}</div>
    <div class="desc">{tier_desc}</div>
    <div class="divider"></div>
    <div class="note">
      We use Discord to <b>identify your account</b> and assign your role automatically after payment.<br>
      We only request your username and avatar — nothing else.
    </div>
    <a href="{oauth_url}" class="btn">
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057c.002.022.015.043.033.056a19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
      Continue with Discord
    </a>
  </div>
  <div class="sub">You will be redirected to Discord to authorize, then to Stripe to complete payment.<br>Billing is handled securely by Stripe.</div>
</div>
</body>
</html>"""

    return web.Response(text=html, content_type="text/html")


async def handle_subscribe_callback(request: web.Request) -> web.Response:
    """Exchange Discord code → get user ID → redirect to Stripe with client_reference_id."""
    code = request.rel_url.query.get("code")
    tier = request.rel_url.query.get("state", "")

    if not code or tier not in ("standard", "mentorship"):
        return web.Response(
            text=_page("❌ Auth failed", "Invalid request. Please try again.", "#ff4444"),
            content_type="text/html",
        )

    async with aiohttp.ClientSession() as session:
        async with session.post(f"{DISCORD_API}/oauth2/token", data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": SUBSCRIBE_REDIRECT_URI,
        }) as r:
            if r.status != 200:
                return web.Response(
                    text=_page("❌ Auth failed", "Could not verify your Discord account. Please try again.", "#ff4444"),
                    content_type="text/html",
                )
            token_data = await r.json()

        async with session.get(f"{DISCORD_API}/users/@me",
                               headers={"Authorization": f"Bearer {token_data['access_token']}"}) as r:
            if r.status != 200:
                return web.Response(
                    text=_page("❌ Auth failed", "Could not fetch your Discord profile.", "#ff4444"),
                    content_type="text/html",
                )
            user = await r.json()

    user_id = user["id"]
    stripe_link = STRIPE_STANDARD_LINK if tier == "standard" else STRIPE_MENTORSHIP_LINK

    if not stripe_link:
        return web.Response(
            text=_page("❌ Not configured", "Payment link not set up yet.", "#ff4444"),
            content_type="text/html",
        )

    sep = "&" if "?" in stripe_link else "?"
    raise web.HTTPFound(f"{stripe_link}{sep}client_reference_id={tier}:{user_id}")


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _page(title: str, body: str, color: str = "#9333ea") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0c0a14;font-family:system-ui,sans-serif;display:flex;
     align-items:center;justify-content:center;min-height:100vh;color:#fff}}
.box{{text-align:center;padding:48px 36px;max-width:440px}}
h1{{font-size:22px;font-weight:800;margin-bottom:12px;color:{color}}}
p{{color:rgba(255,255,255,.55);font-size:15px;line-height:1.7}}
</style>
</head>
<body>
<div class="box"><h1>{title}</h1><p>{body}</p></div>
</body>
</html>"""


# ── Stripe webhook ───────────────────────────────────────────────────────────

def _verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify Stripe webhook signature (t=timestamp,v1=hash)."""
    try:
        parts = {k: v for k, v in (p.split("=", 1) for p in sig_header.split(","))}
        timestamp = parts.get("t", "")
        signature = parts.get("v1", "")
        if abs(time.time() - int(timestamp)) > 300:
            return False
        signed = f"{timestamp}.".encode() + payload
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def _price_to_role(price_id: str) -> int | None:
    if price_id == STRIPE_STANDARD_PRICE_ID:
        return STRIPE_STANDARD_ROLE_ID
    if price_id == STRIPE_MENTORSHIP_PRICE_ID:
        return STRIPE_MENTORSHIP_ROLE_ID
    return None


async def _grant_role(bot, discord_user_id: int, role_id: int):
    if not STRIPE_GUILD_ID:
        return
    guild = bot.get_guild(STRIPE_GUILD_ID)
    if not guild:
        return
    role = guild.get_role(role_id)
    if not role:
        return
    try:
        member = guild.get_member(discord_user_id) or await guild.fetch_member(discord_user_id)
        if role not in member.roles:
            await member.add_roles(role, reason="Stripe subscription active")
    except Exception as e:
        log.warning("grant_role failed for %s: %s", discord_user_id, e)


async def _remove_role(bot, discord_user_id: int, role_id: int):
    if not STRIPE_GUILD_ID:
        return
    guild = bot.get_guild(STRIPE_GUILD_ID)
    if not guild:
        return
    role = guild.get_role(role_id)
    if not role:
        return
    try:
        member = guild.get_member(discord_user_id) or await guild.fetch_member(discord_user_id)
        if role in member.roles:
            await member.remove_roles(role, reason="Stripe subscription cancelled/failed")
    except Exception as e:
        log.warning("remove_role failed for %s: %s", discord_user_id, e)


async def handle_stripe_webhook(request: web.Request) -> web.Response:
    payload = await request.read()
    sig = request.headers.get("Stripe-Signature", "")

    if not STRIPE_WEBHOOK_SECRET or not _verify_stripe_signature(payload, sig, STRIPE_WEBHOOK_SECRET):
        return web.Response(status=400, text="Invalid signature")

    event = json.loads(payload)
    event_type = event.get("type", "")
    db = request.app["db"]
    bot = request.app["bot"]

    log.info("Stripe event: %s", event_type)

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]

        # client_reference_id is set by our subscribe flow as "tier:discord_user_id"
        ref = session.get("client_reference_id") or ""
        if ":" in ref:
            tier, uid_str = ref.split(":", 1)
            discord_user_id = int(uid_str) if uid_str.isdigit() else None
        else:
            tier = ""
            discord_user_id = int(ref) if ref.isdigit() else None

        if tier == "standard":
            role_id = STRIPE_STANDARD_ROLE_ID
            price_id = STRIPE_STANDARD_PRICE_ID
        elif tier == "mentorship":
            role_id = STRIPE_MENTORSHIP_ROLE_ID
            price_id = STRIPE_MENTORSHIP_PRICE_ID
        else:
            role_id = None
            price_id = None

        customer_id = session.get("customer")
        subscription_id = session.get("subscription")

        if discord_user_id and customer_id:
            await db.execute(
                """INSERT INTO stripe_subscriptions (stripe_customer_id, discord_user_id, stripe_price_id, stripe_subscription_id, status)
                   VALUES ($1, $2, $3, $4, 'active')
                   ON CONFLICT (stripe_customer_id) DO UPDATE
                   SET discord_user_id=$2, stripe_price_id=$3, stripe_subscription_id=$4, status='active'""",
                customer_id, discord_user_id, price_id, subscription_id,
            )
            if role_id:
                await _grant_role(bot, discord_user_id, role_id)
                log.info("Granted role %s to %s (checkout, tier=%s)", role_id, discord_user_id, tier)

    elif event_type == "invoice.paid":
        invoice = event["data"]["object"]
        customer_id = invoice.get("customer")
        price_id = None
        for line in invoice.get("lines", {}).get("data", []):
            price_id = line.get("price", {}).get("id")
            break

        row = await db.fetchrow(
            "SELECT discord_user_id FROM stripe_subscriptions WHERE stripe_customer_id=$1", customer_id
        )
        if row:
            await db.execute(
                "UPDATE stripe_subscriptions SET status='active', stripe_price_id=$2 WHERE stripe_customer_id=$1",
                customer_id, price_id or row["stripe_price_id"],
            )
            role_id = _price_to_role(price_id) if price_id else None
            if role_id:
                await _grant_role(bot, row["discord_user_id"], role_id)

    elif event_type in ("customer.subscription.deleted", "invoice.payment_failed"):
        obj = event["data"]["object"]
        customer_id = obj.get("customer")
        row = await db.fetchrow(
            "SELECT discord_user_id, stripe_price_id FROM stripe_subscriptions WHERE stripe_customer_id=$1", customer_id
        )
        if row:
            await db.execute(
                "UPDATE stripe_subscriptions SET status='cancelled' WHERE stripe_customer_id=$1", customer_id
            )
            role_id = _price_to_role(row["stripe_price_id"]) if row["stripe_price_id"] else None
            if role_id:
                await _remove_role(bot, row["discord_user_id"], role_id)
                log.info("Removed role %s from %s (%s)", role_id, row["discord_user_id"], event_type)

    return web.Response(status=200, text="ok")


# ── App factory ───────────────────────────────────────────────────────────────

def make_app(pool, bot) -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app["db"] = pool
    app["bot"] = bot

    app.router.add_get("/verify", handle_verify)
    app.router.add_get("/callback", handle_callback)
    app.router.add_get("/api/members", handle_members)
    app.router.add_get("/api/servers", handle_servers)
    app.router.add_post("/api/pull", handle_pull)
    app.router.add_delete("/api/members/deauthorized", handle_delete_deauth)
    app.router.add_delete("/api/members/{user_id}", handle_delete_member)
    app.router.add_post("/stripe/webhook", handle_stripe_webhook)
    app.router.add_get("/subscribe", handle_subscribe)
    app.router.add_get("/subscribe/callback", handle_subscribe_callback)

    return app


async def run_app(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info("API running on port %d", PORT)
    await asyncio.Event().wait()
