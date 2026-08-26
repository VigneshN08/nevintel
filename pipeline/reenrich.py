"""
Re-run topic and CVE tagging over the whole corpus.

The rules in enrich.py change; the corpus does not. Run this after editing a
topic pattern so existing stories pick up the new rule, instead of only
articles fetched from now on.

Only derived columns are touched. Publisher-authored fields -- title, snippet,
url -- are never rewritten by this or anything else.

    python pipeline/reenrich.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import store  # noqa: E402
from enrich import enrich  # noqa: E402

DB = Path(__file__).resolve().parent.parent / "corpus" / "corpus.db"


def run() -> int:
    if not DB.exists():
        print("  no corpus yet", file=sys.stderr)
        return 1

    changed = 0
    with store.connect(DB) as conn:
        rows = conn.execute("SELECT id, title, snippet, topics, cves FROM article").fetchall()
        for row in rows:
            topics, cves = enrich(row["title"], row["snippet"])
            t, c = ",".join(topics), ",".join(cves)
            if t != row["topics"] or c != row["cves"]:
                store.set_tags(conn, row["id"], t, c)
                changed += 1

    print(f"  re-tagged {changed} of {len(rows)} article(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
