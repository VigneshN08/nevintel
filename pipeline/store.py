"""
SQLite corpus.

The database file is committed to the repository. That is deliberate:

  * it is the full history, so a rebuild never depends on a feed still
    carrying an item (The Record exposes only 5);
  * committing it on every run counts as repository activity, which keeps
    GitHub from auto-disabling the scheduled workflow after 60 days;
  * it gives Phase 2 (NVD/KEV/EPSS) and Phase 4 (the IOC gate) somewhere to
    write without introducing a hosted database.

Only sanitised plain text is ever written here.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = DELETE;   -- keep the committed file a single artifact
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS article (
    id            TEXT PRIMARY KEY,   -- sha256 of the normalised URL
    source_id     TEXT NOT NULL,
    source_name   TEXT NOT NULL,
    title         TEXT NOT NULL,
    url           TEXT NOT NULL UNIQUE,
    domain        TEXT NOT NULL,
    snippet       TEXT NOT NULL DEFAULT '',
    author        TEXT NOT NULL DEFAULT '',
    published_at  TEXT NOT NULL,      -- ISO-8601 UTC
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    topics        TEXT NOT NULL DEFAULT '',  -- comma-separated topic ids
    cves          TEXT NOT NULL DEFAULT ''   -- comma-separated CVE ids
);

CREATE INDEX IF NOT EXISTS idx_article_published ON article(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_article_source    ON article(source_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_article_topics    ON article(topics);

CREATE TABLE IF NOT EXISTS fetch_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id   TEXT NOT NULL,
    ran_at      TEXT NOT NULL,
    status      TEXT NOT NULL,        -- ok | http_error | parse_error | empty
    detail      TEXT NOT NULL DEFAULT '',
    items_seen  INTEGER NOT NULL DEFAULT 0,
    items_new   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_fetchlog_ran ON fetch_log(ran_at DESC);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def article_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


# Columns added after the first release. SQLite has no "ADD COLUMN IF NOT
# EXISTS", so we check pragma output and add what is missing. This keeps an
# already-committed corpus intact across upgrades instead of forcing a rebuild.
MIGRATIONS = {
    "topics": "ALTER TABLE article ADD COLUMN topics TEXT NOT NULL DEFAULT ''",
    "cves":   "ALTER TABLE article ADD COLUMN cves   TEXT NOT NULL DEFAULT ''",
}


def migrate(conn: sqlite3.Connection) -> None:
    have = {r["name"] for r in conn.execute("PRAGMA table_info(article)")}
    for column, ddl in MIGRATIONS.items():
        if column not in have:
            conn.execute(ddl)


@contextmanager
def connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        migrate(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_article(conn: sqlite3.Connection, rec: dict) -> bool:
    """Insert an article. Returns True if it was new.

    Existing rows only ever have last_seen_at touched. We never overwrite a
    stored title or snippet from a later fetch -- a publisher silently
    editing a headline should not rewrite our history, and it keeps the
    generated content files stable so Hugo rebuilds stay cheap.
    """
    ts = now_iso()
    # Derived columns default to empty so callers that pre-date enrichment
    # (and the offline selftest) keep working. A missing tag is a tag we
    # have not computed yet, never an error.
    rec = {"topics": "", "cves": "", **rec}
    existing = conn.execute(
        "SELECT 1 FROM article WHERE id = ?", (rec["id"],)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE article SET last_seen_at = ? WHERE id = ?", (ts, rec["id"])
        )
        return False

    conn.execute(
        """
        INSERT INTO article
            (id, source_id, source_name, title, url, domain, snippet,
             author, published_at, first_seen_at, last_seen_at, topics, cves)
        VALUES
            (:id, :source_id, :source_name, :title, :url, :domain, :snippet,
             :author, :published_at, :ts, :ts, :topics, :cves)
        """,
        {**rec, "ts": ts},
    )
    return True


def set_tags(conn: sqlite3.Connection, aid: str, topics: str, cves: str) -> None:
    """Update derived tags only. Never touches publisher-authored fields."""
    conn.execute(
        "UPDATE article SET topics = ?, cves = ? WHERE id = ?", (topics, cves, aid)
    )


def log_fetch(conn: sqlite3.Connection, source_id: str, status: str,
              detail: str = "", seen: int = 0, new: int = 0) -> None:
    conn.execute(
        """INSERT INTO fetch_log (source_id, ran_at, status, detail, items_seen, items_new)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (source_id, now_iso(), status, detail[:500], seen, new),
    )


def prune_log(conn: sqlite3.Connection, keep: int = 2000) -> None:
    """Keep the log bounded so the committed file does not grow forever."""
    conn.execute(
        """DELETE FROM fetch_log WHERE id NOT IN
           (SELECT id FROM fetch_log ORDER BY id DESC LIMIT ?)""",
        (keep,),
    )


def recent_articles(conn: sqlite3.Connection, limit: int | None = None) -> list[sqlite3.Row]:
    sql = "SELECT * FROM article ORDER BY published_at DESC, first_seen_at DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return conn.execute(sql).fetchall()


def source_health(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT source_id,
               MAX(ran_at) AS last_run,
               (SELECT status FROM fetch_log f2
                 WHERE f2.source_id = f1.source_id
                 ORDER BY f2.id DESC LIMIT 1) AS last_status
        FROM fetch_log f1
        GROUP BY source_id
        ORDER BY source_id
        """
    ).fetchall()


def stats(conn: sqlite3.Connection) -> dict:
    total = conn.execute("SELECT COUNT(*) c FROM article").fetchone()["c"]
    sources = conn.execute("SELECT COUNT(DISTINCT source_id) c FROM article").fetchone()["c"]
    return {"articles": total, "sources": sources}
