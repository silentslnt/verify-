"""HTTP server — OAuth2 callback + REST API for the admin panel."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from urllib.parse import urlencode

import aiohttp
from aiohttp import web

CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "changeme")
PORT = int(os.getenv("PORT", "8080"))

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

    if user_ids == "all":
        rows = await db.fetch(
            "SELECT user_id, access_token FROM verify_members WHERE token_expires_at > now()"
        )
    else:
        ids = [int(uid) for uid in user_ids]
        rows = await db.fetch(
            "SELECT user_id, access_token FROM verify_members WHERE user_id = ANY($1) AND token_expires_at > now()",
            ids,
        )

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

    return app


async def run_app(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info("API running on port %d", PORT)
    await asyncio.Event().wait()
