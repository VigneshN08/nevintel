"""
Turn the SQLite corpus into Hugo content files and dashboard data.

Every value written here has already been sanitised at ingest. This module
still treats it as untrusted: all front-matter is emitted as JSON, so a title
containing quotes, colons or newlines cannot break out of the front-matter
block and inject Hugo directives.

Content bodies are intentionally empty. A story page is a stub that attributes
and links out; the snippet lives in front-matter and is rendered through
Hugo's normal escaping. There is no Markdown body for a publisher's text to
hide in.

ON SIGNAL HONESTY
-----------------
The dashboard shows badges and counters. Every one of them is derived from
something we can point at:

  * "CVE LINKED" means a CVE identifier appears in the text we hold. It is a
    claim about the article, not about the vulnerability.
  * Counters count rows in our own corpus.
  * Topic tags come from published keyword rules in enrich.py that anyone can
    read and check.

Nothing here asserts that an indicator is malicious, that a story is
"verified", or that a flaw is "critical". Those require evidence we do not
have until Phase 2 (KEV/EPSS/CVSS) and Phase 4 (the IOC gate). Rendering a
confident-looking badge over an unverified claim is how an aggregator becomes
a liability, so the badge vocabulary here is deliberately narrower than the
design could support.
"""

from __future__ import annotations

import json
import shutil
import sys
import tomllib
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import store  # noqa: E402
from enrich import topic_meta  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "corpus" / "corpus.db"
SOURCES = Path(__file__).parent / "sources.toml"
CONTENT = ROOT / "content" / "story"
DATA_OUT = ROOT / "data" / "site.json"

# The corpus keeps everything; this only bounds the generated site. Raise it
# freely -- Hugo builds ~1,600 pages/sec and GitHub Pages has no file limit.
MAX_PAGES = 20000

# How many stories the dashboard renders inline. The rest are reachable
# through search and their own pages.
FEED_LIMIT = 60
RAIL_LIMIT = 8


def slugify(text: str, aid: str) -> str:
    slug = "".join(c.lower() if c.isalnum() else "-" for c in text)
    while "--" in slug:
        slug = slug.replace("--", "-")
    slug = slug.strip("-")[:70].strip("-")
    return f"{slug}-{aid[:8]}" if slug else aid


def load_source_meta() -> dict[str, dict]:
    with SOURCES.open("rb") as fh:
        cfg = tomllib.load(fh)
    return {
        s["id"]: {
            "id": s["id"],
            "name": s["name"],
            "home": s.get("home", ""),
            "kind": s.get("kind", "news"),
            "short": s.get("short", s["id"][:2].upper()),
            "hue": s.get("hue", 190),
            "headlineOnly": int(s.get("snippet_words", 25)) == 0,
            "licenceNote": s.get("licence_note", ""),
        }
        for s in cfg.get("source", [])
    }


def split(field: str | None) -> list[str]:
    return [v for v in (field or "").split(",") if v]


def row_to_item(row, meta: dict[str, dict]) -> dict:
    src = meta.get(row["source_id"], {})
    return {
        "id": row["id"],
        "title": row["title"],
        "url": row["url"],
        "domain": row["domain"],
        "snippet": row["snippet"],
        "author": row["author"],
        "date": row["published_at"],
        "slug": slugify(row["title"], row["id"]),
        "sourceId": row["source_id"],
        "sourceName": row["source_name"],
        "sourceHome": src.get("home", ""),
        "short": src.get("short", "?"),
        "hue": src.get("hue", 190),
        "topics": split(row["topics"]),
        "cves": split(row["cves"]),
    }


def write_story(item: dict, out_dir: Path) -> None:
    front = {
        "title": item["title"],
        "date": item["date"],
        "slug": item["slug"],
        "layout": "story",
        "params": {
            "sourceName": item["sourceName"],
            "sourceId": item["sourceId"],
            "sourceHome": item["sourceHome"],
            "originalUrl": item["url"],
            "domain": item["domain"],
            "snippet": item["snippet"],
            "author": item["author"],
            "topics": item["topics"],
            "cves": item["cves"],
            "short": item["short"],
            "hue": item["hue"],
        },
    }
    body = "---\n" + json.dumps(front, indent=2, ensure_ascii=False) + "\n---\n"
    (out_dir / f"{item['id']}.md").write_text(body, encoding="utf-8")


def run() -> int:
    if not DB.exists():
        print("  no corpus yet -- run fetch.py first", file=sys.stderr)
        return 1

    meta = load_source_meta()

    # Rebuild the generated tree from scratch so deleted or re-slugged stories
    # cannot leave orphan pages behind.
    if CONTENT.exists():
        shutil.rmtree(CONTENT)
    CONTENT.mkdir(parents=True)

    with store.connect(DB) as conn:
        rows = store.recent_articles(conn, MAX_PAGES)
        st = store.stats(conn)

        sources = [
            dict(r)
            for r in conn.execute(
                """
                SELECT h.source_id                          AS id,
                       COALESCE(a.source_name, h.source_id) AS name,
                       COALESCE(a.n, 0)                     AS held,
                       h.last_run                           AS last_run,
                       h.last_status                        AS last_status,
                       COALESCE(a.newest, '')               AS newest
                FROM (
                    SELECT source_id,
                           MAX(ran_at) AS last_run,
                           (SELECT status FROM fetch_log f2
                             WHERE f2.source_id = f1.source_id
                             ORDER BY f2.id DESC LIMIT 1) AS last_status
                    FROM fetch_log f1 GROUP BY source_id
                ) h
                LEFT JOIN (
                    SELECT source_id, source_name, COUNT(*) n,
                           MAX(published_at) newest
                    FROM article GROUP BY source_id
                ) a ON a.source_id = h.source_id
                ORDER BY held DESC, name
                """
            )
        ]

    for src in sources:
        src.update({k: v for k, v in meta.get(src["id"], {}).items()
                    if k in ("home", "kind", "short", "hue", "headlineOnly", "licenceNote")})
        src.setdefault("short", "?")
        src.setdefault("hue", 190)
        src.setdefault("home", "")

    items = [row_to_item(r, meta) for r in rows]
    for item in items:
        write_story(item, CONTENT)

    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

    recent_week = [i for i in items if i["date"] >= week_ago]

    # Trending topics: frequency over the last 7 days, not all time, so the
    # panel reflects what is happening rather than what the corpus contains.
    topic_counts = Counter(t for i in recent_week for t in i["topics"])
    cve_counts = Counter(c for i in recent_week for c in i["cves"])

    labels = {t["id"]: t for t in topic_meta()}
    trending = [
        {**labels[tid], "count": n}
        for tid, n in topic_counts.most_common(10)
        if tid in labels
    ]

    live = {
        "storiesToday": sum(1 for i in items if i["date"] >= day_ago),
        "storiesWeek": len(recent_week),
        "cvesWeek": len(cve_counts),
        "sourcesOk": sum(1 for s in sources if s["last_status"] in ("ok", "not_modified")),
        "sourcesTotal": len(sources),
    }

    DATA_OUT.parent.mkdir(parents=True, exist_ok=True)
    DATA_OUT.write_text(
        json.dumps(
            {
                "builtAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "articles": st["articles"],
                "sources": st["sources"],
                "rendered": len(items),
                "live": live,
                "lead": items[0] if items else None,
                "feed": items[:FEED_LIMIT],
                "rail": items[:RAIL_LIMIT],
                "topics": topic_meta(),
                "trending": trending,
                "topCves": [{"id": c, "count": n} for c, n in cve_counts.most_common(8)],
                "sources_detail": sources,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"  rendered {len(items)} story page(s); "
          f"{len(trending)} trending topic(s), {live['cvesWeek']} CVE(s) this week")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
