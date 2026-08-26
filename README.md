# NEVINTEL

A static cybersecurity news aggregator that rebuilds itself every two hours.

No server. No database behind the page. No code running when a visitor arrives.
A scheduled GitHub Actions job fetches feeds, sanitises everything, stores it in
a SQLite file kept in this repository, and rebuilds the site as plain HTML.

**Phases 1–3, plus part of 4.** Feeds, sanitisation, corpus, dashboard,
browser-side search, topic classification, CVE extraction, and faceted
filtering all work today. Structured vulnerability data (KEV/EPSS/NVD),
network indicators, and own-words summaries come next — see
[Roadmap](#roadmap).

### Signal honesty

Every badge and counter on the page is derived from something checkable:

- **CVE tags** mean a CVE identifier appears in the text we hold. That is a
  claim about the *article*, not a verified assessment of the vulnerability.
- **Topic tags** come from published keyword rules in `pipeline/enrich.py`.
  A headline match scores higher than a snippet match, and a topic needs
  converging signals rather than one stray word. Anyone can read the rule
  that produced any tag; the Story Explainer panel shows it in the UI.
- **Counters** count rows in our own corpus. There is deliberately no
  "attacks today" figure, because we have no way to measure one.

Nothing here asserts that a story is "verified", that an indicator is
malicious, or that a flaw is "critical". Those need evidence we do not have
until Phase 2 and Phase 4. A confident-looking badge over an unverified claim
is how an aggregator becomes a liability.

---

## Setup

Five things to change before the first build.

**1. Fork or create the repo — and keep it public.**
Public repositories get unlimited free GitHub Actions minutes on standard
runners. Private ones get 2,000/month, which at 360 builds leaves 5.5 minutes
per build. Public is not just cheaper here; it is the difference between the
project working and not.

**2. Replace the placeholders.**

| Placeholder | Where | Replace with |
|---|---|---|
| `VigneshN08` | `hugo.toml`, `pipeline/sources.toml`, `content/about.md` | your GitHub username |
| `nemmikantivignesh17@gmail.com` | `hugo.toml`, `pipeline/sources.toml` | a real address you monitor |
| `subscribeEndpoint` | `hugo.toml` | a Buttondown / Listmonk / Formspree URL — see below |

```bash
grep -rl 'VigneshN08\|nemmikantivignesh17@gmail.com' --exclude-dir=.git . \
  | xargs sed -i 's|VigneshN08|your-username|g; s|nemmikantivignesh17@gmail.com|you@example.com|g'
```

The takedown address is not decoration. Most publisher disputes end with a
polite email being answered, and there is no cheaper form of insurance.

**2b. Email signup.** A static site has no server to receive a POST, so the
subscribe forms need a third-party endpoint. Set `subscribeEndpoint` in
`hugo.toml` to a Buttondown, Listmonk or Formspree URL. Left empty, both forms
render **disabled with an explanation** rather than silently discarding
addresses — a signup box that drops emails is worse than no signup box, because
people believe they subscribed.

**3. Enable Pages.** Settings → Pages → Source: **GitHub Actions**.

**4. Run it once.** Actions → `build` → *Run workflow*. The first run backfills
whatever the feeds are currently exposing, then commits the corpus.

**5. Put Cloudflare in front (recommended).** GitHub Pages has a 100 GB/month
soft bandwidth limit and cannot set response headers. Fronting it with a free
Cloudflare zone fixes both and lets you set a Content-Security-Policy. Note
Pagefind needs `script-src 'wasm-unsafe-eval'`.

---

## Running it locally

```bash
pip install -r pipeline/requirements.txt

python pipeline/selftest.py     # 49 sanitiser/corpus/enrichment checks, no network
python pipeline/fetch.py        # pull feeds into corpus/corpus.db
python pipeline/reenrich.py     # re-tag the corpus after editing enrich.py
python pipeline/render.py       # corpus -> content/story/*.md + data/site.json
hugo server                     # http://localhost:1313
```

To build exactly as CI does:

```bash
hugo --minify --gc
npx pagefind@1.3.0 --site public
```

---

## How it fits together

```
pipeline/sources.toml     which feeds, and each one's snippet cap
        │
pipeline/fetch.py         HTTP + conditional requests + retry
        │                 ↓ sanitise at ingest, before storage
pipeline/sanitize.py      feed HTML -> plain text; URL scheme allowlist
        │
corpus/corpus.db          SQLite, committed to the repo
        │
pipeline/render.py        corpus -> content/story/*.md + data/site.json
        │
Hugo                      147 pages in ~120 ms
        │
Pagefind                  chunked search index
        │
GitHub Pages              behind Cloudflare
```

`corpus/` rather than `data/` because Hugo reserves `data/` for template data
and tries to parse everything in it — a SQLite file there fails the build.

---

## The four decisions worth understanding

### Sanitise at build time, or not at all

`pipeline/sanitize.py` is the most important file here.

RSS `<description>` and `<content:encoded>` fields carry attacker-controllable
HTML by design. Pipe one into a template with `safeHTML` and an `<img onerror>`
from a compromised upstream feed is baked permanently into the static output
and served with this domain's authority. **Being static provides zero
protection against this** — the payload is in the artifact.

So: everything is reduced to plain text on the ingest path, by a real HTML5
parser (`nh3`, the Rust `ammonia` bindings), iterating to a fixed point so a
double- or triple-encoded payload cannot re-materialise. Snippets are stored as
text, never HTML. There is no `safeHTML` anywhere in this repository and there
must never be. `goldmark.renderer.unsafe` is `false` as a second line.

URLs get an allowlist too: anything that is not plainly `http` or `https` is
dropped rather than rendered. `javascript:`, `data:`, `vbscript:`,
protocol-relative — a link we cannot vouch for is a link we do not publish.

`python pipeline/selftest.py` proves all of the above against 37 hostile
inputs. Run it before every change to that file.

### Snippets are capped for a specific legal reason

In *AP v. Meltwater* (S.D.N.Y. 2013) a commercial service that delivered
**headlines plus opening paragraphs** with links was held **not** fair use. The
court singled out the lede as taking "significant journalistic skill to craft,"
called the service "a classic news clipping service," and declined to treat a
permissive `robots.txt` as a defence.

An article's opening paragraph is exactly what most RSS `<description>` fields
hand you. The default behaviour of every RSS-aggregator tutorial is the
specific act that lost that case.

Hence: 25 words maximum, per source, configurable down to zero. Sources whose
licence prohibits commercial reuse (SANS ISC is CC BY-NC) get `snippet_words = 0`
— headline and link only. A full-text feed is **not** a licence to republish;
Krebs, Talos, Schneier and Project Zero all publish one, and the fetcher
deliberately prefers the shorter `summary` field anyway.

The counterweight, and the thing this product is actually built on: in
*Barclays v. Theflyonthewall* (2d Cir. 2011) the "hot news" doctrine was held
preempted by copyright. **Reporting the facts another outlet broke — promptly,
commercially — is not actionable, provided you write your own words.** Facts
are free; expression is not. For a security site the facts *are* the product:
CVE IDs, vendors, affected versions, actor names, patch dates. That is what
Phase 5 leans into.

### The build pipeline is the attack surface

A static site removes SQL injection, SSRF, RCE, session handling, the database,
and the patch treadmill. What it does not remove is CI — which now has write
access to what every visitor executes. That is a *better* target than a web
server, and it is being actively exploited:

- **May 2026, "Mini Shai-Hulud":** an npm payload ran on `npm install`, scanned
  `/proc` to find the GitHub Actions runner process and pulled secrets from its
  memory, bypassing log masking. GitHub removed 640 malicious package versions
  and invalidated 61,274 npm tokens.
- **March 2025, `tj-actions/changed-files` (CVE-2025-30066):** a GitHub Action
  was retagged to dump CI secrets into public logs across ~23,000 repositories.
  CISA issued an alert.

What this repo does about it:

- **Hugo, not an npm-based generator.** One checksummed Go binary; dependency
  tree of size zero. Zola would work identically.
- **Every action pinned to a full commit SHA**, never a tag. GitHub's own
  wording: pinning to a SHA "is currently the only way to use an action as an
  immutable release." Tags are mutable — that is exactly the tj-actions vector.
- **Hash-pinned Python dependencies**, installed with `--require-hashes`.
- **Least-privilege `GITHUB_TOKEN`** — read by default, elevated per job.
- **Dependabot on both ecosystems**, so pins get bumped deliberately.

Two things this repo cannot do for you, and both matter more than anything
above: put **hardware 2FA on your registrar, DNS and CDN accounts separately**
(whoever controls the DNS record controls what every visitor executes, and no
code review catches that), and **audit for dangling CNAMEs** — GitHub Pages
subdomain takeover is actively exploited.

### Two hours is a target, not a guarantee

GitHub's documentation on scheduled workflows says runs "can be delayed during
periods of high loads" and that "some queued jobs may be dropped." The top of
the hour is the worst offender, because that is when everyone else's cron
fires.

- The schedule is `37 */2 * * *`. Never `0 */2`.
- `workflow_dispatch` is enabled so a dropped run can be kicked manually, or by
  an external pinger (cron-job.org, a Cloudflare Worker cron) hitting the API.
- The footer shows the **real last-build timestamp**, not the schedule. If a
  run is dropped, readers can see that rather than assume freshness.
- Scheduled workflows on public repos auto-disable after 60 days with no
  repository activity. The corpus commit on each run is what keeps this alive —
  do not remove it.
- Incidentally, NVD's own guidance is to poll no more often than every two
  hours. The cadence is on the right side of that line.

---

## Adding a source

Append to `pipeline/sources.toml`:

```toml
[[source]]
id   = "shortname"        # stable; used in URLs and the health table
name = "Display Name"
url  = "https://example.com/feed/"
home = "https://example.com/"
kind = "news"             # or "research"
# snippet_words = 0       # set to 0 for any non-commercial licence
```

Before you add one, check its licence. Ad-supported counts as commercial, so
every "non-commercial use only" clause applies to this site. If in doubt, set
`snippet_words = 0` and show headline and link only.

The `/sources/` page reports every feed's last fetch outcome in public. A
source showing `http_error` is usually a publisher blocking datacenter traffic
(BleepingComputer does) rather than an outage — the fetcher retries once with a
browser user-agent and logs either way. One bad feed never fails the build;
*every* feed failing does, so the site cannot go silently stale for weeks.

---

## Roadmap

| Phase | What | Status |
|---|---|---|
| 1 | Feeds, sanitisation, corpus, site, search | **done** |
| 2 | CISA KEV, NVD, EPSS, OSV, GHSA — all CC0 or public-domain-equivalent | next |
| 3 | Faceted filtering by topic, source, age, CVE | **done** |
| 4a | Regex CVE extraction + keyword topic rules (free, deterministic) | **done** |
| 4b | MISP warninglists → schema-constrained LLM → substring proof → actor validation → confidence scoring → defang | |
| 5 | Own-words summaries replacing excerpts; rewritten headlines | |
| 6 | CSP, dangling-CNAME audits, build-failure alerting | ongoing |

Thresholds to watch as the archive grows: **~250k pages** (Pagefind stops being
viable; migrate to self-hosted Meilisearch on a small VPS) and **1 GB** (GitHub
Pages' published-site cap; migrate to Cloudflare R2 with a Worker router).

---

## Cost

Roughly **$1/month** at Phase 1 — a domain, and nothing else. Hosting, CI,
search and the corpus are all $0. Phase 4 adds LLM extraction at an estimated
$4–10/month depending on volume.

---

## Licence

Code: MIT. See `LICENSE`.

The corpus is **not** licensed for redistribution. It contains headlines and
short extracts whose copyright belongs to the publishers listed in
`pipeline/sources.toml`.
