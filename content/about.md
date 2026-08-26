---
title: "About NEVINTEL"
standfirst: "What this is, how it is built, and the rules it operates under."
---

## What it is

NEVINTEL reads a fixed list of cybersecurity news and research feeds every two
hours, organises what it finds, and links back to the publisher. It is a way
to see the day's security reporting in one place without twenty tabs.

It is **not** a mirror. NEVINTEL does not reproduce articles. Each entry carries
the headline, the publisher, a short extract for identification, and a link to
the original — which is where you should read it.

## How it is built

A scheduled job on GitHub Actions fetches the feeds, sanitises everything it
receives, stores it in a SQLite file kept in the repository, and rebuilds this
site as plain HTML. The result is copied to a CDN. There is no application
server, no database behind this page, and no code running when you visit.

That architecture is a security decision, not a cost one. With nothing
executing at request time there is no injection surface, no session handling,
no server to compromise. What it does *not* remove is the build pipeline, so
that is where the hardening effort goes: no npm dependency tree, third-party
actions pinned to commit hashes, and every byte of feed HTML stripped to plain
text before it can reach a template.

The whole thing is open — the [repository](https://github.com/VigneshN08/nevisec)
contains the fetcher, the templates, and the corpus.

## No tracking

No analytics, no cookies, no third-party scripts, no fonts or assets loaded
from anyone else's server except the typeface. Search runs entirely in your
browser against a pre-built index; your queries are never sent anywhere.
Outbound links carry `no-referrer`, so publishers do not learn you arrived
from here unless they can tell from their own logs.

## The rules this site follows

Aggregating other people's journalism has real limits, and NEVINTEL is built
around them rather than hoping nobody notices.

Extracts are hard-capped at roughly twenty-five words and are taken from the
publisher's own feed summary. Sources whose licence prohibits commercial reuse
get headline and link only — no extract at all. Full articles are never
reproduced, even where a feed offers the full text; a feed is published for
readers, not for republishers. Publisher images are never rehosted. No page
here frames or embeds another site's content.

Facts are treated differently from expression, because the law treats them
differently. A CVE number, an affected product, a patch date, an attributed
actor — those are facts, and NEVINTEL reports them freely in its own words.
The sentences a journalist wrote around them belong to that journalist.

If you publish something indexed here and want it changed or removed, write to
the address in the footer. Requests get answered, not filed.

## What is coming

This is the first working version. Next: structured vulnerability data from
CISA's Known Exploited Vulnerabilities catalogue, NVD and EPSS, so you can see
what is actually being exploited ranked by likelihood. After that, verified
indicators of compromise — extracted, cross-checked against authoritative
sources, and always published defanged.
