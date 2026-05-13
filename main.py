"""Entry point — runs the Discord bot and HTTP server in the same process."""
import asyncio
import os

import asyncpg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
TOKEN = os.getenv("DISCORD_TOKEN")

SCHEMA = """
CREATE TABLE IF NOT EXISTS verify_config (
    guild_id            BIGINT PRIMARY KEY,
    verify_url          TEXT,
    role_id             BIGINT,
    unverified_role_id  BIGINT,
    verify_channel_id   BIGINT,
    image_url           TEXT,
    panel_msg           TEXT
);
-- add columns to existing deployments
ALTER TABLE verify_config ADD COLUMN IF NOT EXISTS unverified_role_id BIGINT;
ALTER TABLE verify_config ADD COLUMN IF NOT EXISTS verify_channel_id  BIGINT;
CREATE TABLE IF NOT EXISTS stripe_subscriptions (
    stripe_customer_id      TEXT PRIMARY KEY,
    discord_user_id         BIGINT NOT NULL,
    stripe_price_id         TEXT,
    stripe_subscription_id  TEXT,
    status                  TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS verify_members (
    user_id          BIGINT PRIMARY KEY,
    username         TEXT,
    avatar           TEXT,
    access_token     TEXT NOT NULL,
    refresh_token    TEXT,
    token_expires_at TIMESTAMPTZ,
    verified_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_guild_id  BIGINT
);
"""


async def main():
    pool = await asyncpg.create_pool(DATABASE_URL)
    await pool.execute(SCHEMA)

    from bot import make_bot
    from api import make_app, run_app

    bot = make_bot(pool)
    app = make_app(pool, bot)

    await asyncio.gather(
        bot.start(TOKEN),
        run_app(app),
    )


if __name__ == "__main__":
    asyncio.run(main())
