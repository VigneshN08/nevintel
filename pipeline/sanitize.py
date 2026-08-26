"""
Build-time HTML sanitisation.

This module is the single most important file in the repository.

RSS <description> and <content:encoded> fields carry attacker-controllable
HTML by design. If any of it reaches a Hugo template unsanitised, an
<img onerror=...> in a compromised upstream feed gets baked permanently into
our static output and served with our own domain's authority. Being a static
site provides ZERO protection against this -- the payload is in the artifact.

Rules enforced here:
  1. Everything is sanitised at build time, on the runner, before storage.
     Never in the browser.
  2. Snippets are stored as PLAIN TEXT, not HTML. Templates render them with
     Hugo's default escaping. There is no `safeHTML` anywhere in this repo,
     and there must never be.
  3. Snippets are word-capped per source (see sources.toml and AP v.
     Meltwater in the README).
"""

from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import urlparse, urlunparse

import nh3

# Nothing is allowed through. We keep no tags at all, because we store plain
# text. This set exists so that a future change is a deliberate edit rather
# than an accidental widening.
ALLOWED_TAGS: set[str] = set()
ALLOWED_ATTRS: dict[str, set[str]] = {}

_WS = re.compile(r"\s+")
_TRAIL = re.compile(r"[\s….,;:\-–—]+$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Publishers append these to truncated feed excerpts.
_FEED_CRUFT = re.compile(
    r"\s*(\[(?:…|\.\.\.|read more)\]|"
    r"(?:continue reading|read more|read the full (?:story|article)|"
    r"the post .{0,120} appeared first on .{0,80})\s*[.…]?)\s*$",
    re.IGNORECASE,
)


def strip_html(raw: str | None) -> str:
    """Reduce arbitrary feed HTML to safe plain text.

    nh3 (Rust ammonia bindings) does the parsing, so malformed markup,
    nested-tag smuggling and entity tricks are handled by a real HTML5
    parser rather than a regex. We then unescape once and normalise.
    """
    if not raw:
        return ""

    # Clean, decode, repeat until the value stops changing.
    #
    # One pass is not enough. A payload encoded twice upstream
    # (&amp;lt;script&amp;gt;) survives a single clean-then-unescape as the
    # literal text "&lt;script&gt;" -- harmless where we render it, but it
    # would become live markup for anyone who later decoded it once more.
    # Iterating to a fixed point means the stored value is fully decoded
    # plain text with no markup left at any encoding depth. The bound stops
    # a pathological input from spinning.
    text = raw
    for _ in range(4):
        cleaned = nh3.clean(
            text,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRS,
            strip_comments=True,
            link_rel=None,
        )
        decoded = html.unescape(cleaned)
        if decoded == text:
            break
        text = decoded

    text = unicodedata.normalize("NFKC", text)
    text = _CTRL.sub(" ", text)
    text = _WS.sub(" ", text).strip()
    return text


def clean_title(raw: str | None) -> str:
    """Titles get the same treatment; they are plain text everywhere."""
    return strip_html(raw)[:300]


def snippet(raw: str | None, max_words: int) -> str:
    """Sanitise, de-cruft and hard-cap an excerpt.

    max_words == 0 means the source is headline-and-link only.
    """
    if max_words <= 0:
        return ""

    text = strip_html(raw)
    if not text:
        return ""

    text = _FEED_CRUFT.sub("", text).strip()

    words = text.split(" ")
    if len(words) <= max_words:
        return text

    clipped = " ".join(words[:max_words])
    clipped = _TRAIL.sub("", clipped)
    return clipped + "…"


# --------------------------------------------------------------------------
# Link handling
# --------------------------------------------------------------------------

_SAFE_SCHEMES = {"http", "https"}

# Tracking parameters. Stripped so that identical articles arriving from two
# feeds normalise to the same URL for dedup, and so we do not forward the
# publisher's analytics identifiers to our readers.
_TRACKING_PREFIXES = ("utm_", "pk_", "mtm_", "hsa_", "vero_", "mc_")
_TRACKING_EXACT = {
    "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "twclid",
    "igshid", "mkt_tok", "ref", "referrer", "source", "amp",
    "__s", "_hsenc", "_hsmi", "yclid", "ttclid", "li_fat_id",
}


def safe_url(raw: str | None) -> str:
    """Return a normalised http(s) URL, or '' if it is not one.

    Anything that is not plainly http or https -- javascript:, data:,
    vbscript:, file:, protocol-relative, or malformed -- is dropped rather
    than rendered. A link we cannot vouch for is a link we do not publish.
    """
    if not raw:
        return ""

    candidate = _CTRL.sub("", raw).strip()
    if not candidate:
        return ""

    try:
        parts = urlparse(candidate)
    except ValueError:
        return ""

    if parts.scheme.lower() not in _SAFE_SCHEMES:
        return ""
    if not parts.netloc:
        return ""

    query = "&".join(
        pair
        for pair in parts.query.split("&")
        if pair
        and not pair.split("=", 1)[0].lower().startswith(_TRACKING_PREFIXES)
        and pair.split("=", 1)[0].lower() not in _TRACKING_EXACT
    )

    return urlunparse(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.params, query, "")
    )


def domain_of(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host
