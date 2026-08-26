"""
Feed fetcher.

Design notes:
  * One source failing must never fail the run. A publisher returning 403 to
    datacenter IPs (BleepingComputer does) is normal weather, not an outage.
  * Every fetch outcome is logged to the corpus so the site can show its own
    source health honestly rather than pretending everything is fine.
  * Sanitisation happens here, at ingest, before anything is stored.
  * Conditional requests (ETag / Last-Modified) are sent so we are a polite
    client and so repeat runs are cheap.
"""

from __future__ import annotations

import json
import sys
import time
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import httpx

sys.path.insert(0, str(Path(__file__).parent))

import store  # noqa: E402
from enrich import enrich  # noqa: E402
from sanitize import clean_title, domain_of, safe_url, snippet  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "corpus" / "corpus.db"
SOURCES = Path(__file__).parent / "sources.toml"
CACHE = ROOT / "corpus" / "http-cache.json"

# Some publishers block obvious bots. A plain browser UA is the documented
# fallback; we still identify ourselves in the primary UA and honour any
# takedown request.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

# Items older than this on first sight are ignored, so a feed that suddenly
# exposes its full archive does not backfill the front page with 2019 news.
MAX_AGE_DAYS = 45


def load_sources() -> tuple[dict, list[dict]]:
    with SOURCES.open("rb") as fh:
        cfg = tomllib.load(fh)
    return cfg.get("defaults", {}), cfg.get("source", [])


def load_cache() -> dict:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def save_cache(cache: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")


def parse_date(entry) -> str | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                dt = datetime(*parsed[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
            # Guard against feeds with clocks in the future.
            if dt > datetime.now(timezone.utc) + timedelta(hours=12):
                dt = datetime.now(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def entry_body(entry) -> str:
    """Prefer the short summary over full content.

    We deliberately reach for `summary` first even when `content` is
    available. A full-text feed is not a licence to republish, and the
    snippet is capped either way -- but taking the shorter field keeps the
    stored excerpt further from the article's lede.
    """
    if entry.get("summary"):
        return entry["summary"]
    content = entry.get("content")
    if content and isinstance(content, list) and content:
        return content[0].get("value", "")
    return ""


def fetch_one(client: httpx.Client, src: dict, defaults: dict, cache: dict):
    """Return (status, detail, raw_bytes_or_None)."""
    headers = {"User-Agent": defaults.get("user_agent", "NeviSec/0.1")}
    cached = cache.get(src["id"], {})
    if cached.get("etag"):
        headers["If-None-Match"] = cached["etag"]
    if cached.get("last_modified"):
        headers["If-Modified-Since"] = cached["last_modified"]

    for attempt, ua in enumerate((headers["User-Agent"], BROWSER_UA)):
        headers["User-Agent"] = ua
        try:
            resp = client.get(src["url"], headers=headers, follow_redirects=True)
        except httpx.HTTPError as exc:
            if attempt == 1:
                return "http_error", f"{type(exc).__name__}: {exc}", None
            time.sleep(2)
            continue

        if resp.status_code == 304:
            return "not_modified", "304", None
        if resp.status_code == 200:
            cache[src["id"]] = {
                "etag": resp.headers.get("etag", ""),
                "last_modified": resp.headers.get("last-modified", ""),
                "checked": store.now_iso(),
            }
            return "ok", "", resp.content
        if attempt == 1 or resp.status_code not in (403, 406, 429, 503):
            return "http_error", f"HTTP {resp.status_code}", None
        time.sleep(2)

    return "http_error", "exhausted retries", None


def run() -> int:
    defaults, sources = load_sources()
    cache = load_cache()
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    total_new = 0
    failures: list[str] = []

    timeout = httpx.Timeout(defaults.get("timeout", 20))
    with httpx.Client(timeout=timeout) as client, store.connect(DB) as conn:
        first_run = store.stats(conn)["articles"] == 0

        for src in sources:
            cap = int(src.get("snippet_words", defaults.get("snippet_words", 25)))
            status, detail, body = fetch_one(client, src, defaults, cache)

            if status != "ok":
                store.log_fetch(conn, src["id"], status, detail)
                if status == "http_error":
                    failures.append(f"{src['id']}: {detail}")
                    print(f"  [warn] {src['name']}: {detail}", flush=True)
                else:
                    print(f"  [skip] {src['name']}: not modified", flush=True)
                continue

            parsed = feedparser.parse(body)
            if parsed.bozo and not parsed.entries:
                msg = str(getattr(parsed, "bozo_exception", "unparseable"))
                store.log_fetch(conn, src["id"], "parse_error", msg)
                failures.append(f"{src['id']}: parse error")
                print(f"  [warn] {src['name']}: parse error -- {msg}", flush=True)
                continue

            seen = new = 0
            for entry in parsed.entries:
                url = safe_url(entry.get("link"))
                title = clean_title(entry.get("title"))
                if not url or not title:
                    continue

                published = parse_date(entry)
                if not published:
                    published = store.now_iso()
                elif not first_run and datetime.strptime(
                    published, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc) < cutoff:
                    continue

                seen += 1
                snip = snippet(entry_body(entry), cap)
                topics, cves = enrich(title, snip)
                rec = {
                    "id": store.article_id(url),
                    "source_id": src["id"],
                    "source_name": src["name"],
                    "title": title,
                    "url": url,
                    "domain": domain_of(url),
                    "snippet": snip,
                    "author": clean_title(entry.get("author", ""))[:120],
                    "published_at": published,
                    "topics": ",".join(topics),
                    "cves": ",".join(cves),
                }
                if store.upsert_article(conn, rec):
                    new += 1

            total_new += new
            store.log_fetch(conn, src["id"], "ok" if seen else "empty",
                            seen=seen, new=new)
            print(f"  [ ok ] {src['name']}: {seen} items, {new} new", flush=True)

        store.prune_log(conn)
        final = store.stats(conn)

    save_cache(cache)

    print(f"\n  {total_new} new article(s); corpus now holds "
          f"{final['articles']} across {final['sources']} source(s).")

    # A single source failing is weather. Every source failing is an outage,
    # and the run should go red so it is not silently stale for weeks.
    if failures and len(failures) == len(sources):
        print("\n  ERROR: every source failed.", file=sys.stderr)
        for line in failures:
            print(f"    {line}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
