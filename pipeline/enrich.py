"""
Deterministic enrichment: topics and CVE identifiers.

No LLM, no API key, no per-article cost. Everything here is regex and keyword
matching over text we already hold, which means it is free, instant, and --
most importantly -- auditable. You can read the rule that produced any tag.

This is deliberately the FIRST layer of the IOC pipeline described in the
roadmap, not a placeholder for it. Published research on IOC extraction puts
regex at roughly 70% F1 and an LLM pass at 97.6%, but the two fail in
different directions: regex over-captures things that merely look like
indicators, while the LLM invents things that were never there. The design is
to compose them -- regex sweeps for recall, and later stages verify. Nothing
here is ever trusted enough to publish as "confirmed malicious"; a CVE tag
says "this article mentions this identifier", which is a claim we can prove.

Phase 4 adds: MISP warninglist suppression, a schema-constrained LLM pass,
substring proof against source text, and per-field confidence.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# CVE identifiers
# ---------------------------------------------------------------------------
# Format is fixed by MITRE: CVE-YYYY-NNNN with 4 or more sequence digits.
# Case-insensitive because feeds are inconsistent; normalised to upper.
CVE_RE = re.compile(r"\bCVE[-‑\s]?(\d{4})[-‑\s]?(\d{4,7})\b", re.IGNORECASE)

# Sanity bounds. CVE began in 1999; anything claiming a far-future year is a
# parsing artifact (a phone number, a product code) rather than a real ID.
CVE_MIN_YEAR = 1999
CVE_MAX_YEAR = 2100


def extract_cves(*texts: str) -> list[str]:
    """Return normalised, de-duplicated CVE IDs in first-seen order."""
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for year, seq in CVE_RE.findall(text):
            if not (CVE_MIN_YEAR <= int(year) <= CVE_MAX_YEAR):
                continue
            cve = f"CVE-{year}-{seq}"
            if cve not in seen:
                seen.add(cve)
                found.append(cve)
    return found


# ---------------------------------------------------------------------------
# Topics
# ---------------------------------------------------------------------------
# Ordered most-specific first: an article about a ransomware crew exploiting a
# zero-day should read as ransomware, not merely "vulnerability". Each topic
# needs two independent signals OR one strong one, which keeps a passing
# mention from mislabelling the whole story.

TOPICS: list[dict] = [
    {
        "id": "ransomware",
        "label": "Ransomware",
        "blurb": "Extortion operations: encryption, data-leak sites, and the "
                 "crews and affiliates running them.",
        "strong": [r"\bransomware\b", r"\bransom note\b", r"\bdouble extortion\b",
                   r"\bleak sites?\b", r"\bencrypt(?:ed|s|ing) (?:files|systems|servers)\b"],
        "weak": [r"\bextortion\b", r"\bdecrypt(?:or|ion key)\b", r"\bransom\b",
                 r"\blockbit\b", r"\bblackcat\b", r"\balphv\b", r"\bclop\b",
                 r"\bakira\b", r"\bplay ransomware\b", r"\brhysida\b"],
    },
    {
        "id": "breach",
        "label": "Data Breach",
        "blurb": "Confirmed exposure or theft of records, and the disclosure "
                 "and notification that follows.",
        "strong": [r"\bdata breach\b", r"\bbreach(?:ed|es)? (?:of|at)\b",
                   r"\bexposed \d[\d,.]* (?:million |thousand )?(?:records|customers|users|accounts)\b",
                   r"\bdata leak\b"],
        "weak": [r"\bstolen data\b", r"\bcompromised (?:records|accounts|customer)\b",
                 r"\bpersonal (?:data|information) (?:of|was|were)\b",
                 r"\bnotif(?:ying|ied) (?:customers|users|individuals)\b", r"\bexfiltrat"],
    },
    {
        "id": "vuln",
        "label": "Vulnerabilities",
        "blurb": "Newly disclosed flaws, patches, and proof-of-concept "
                 "exploit code.",
        "strong": [r"\bCVE-\d{4}-\d{4,7}\b", r"\bzero[- ]day\b", r"\bpatch tuesday\b",
                   r"\bremote code execution\b", r"\bRCE\b",
                   r"\bauthentication bypass\b", r"\bprivilege escalation\b"],
        "weak": [r"\bvulnerabilit(?:y|ies)\b", r"\bexploit(?:ed|able|ation)?\b",
                 r"\bpatch(?:ed|es)?\b", r"\bproof[- ]of[- ]concept\b", r"\bCVSS\b",
                 r"\bsecurity update\b", r"\badvisor(?:y|ies)\b", r"\bflaw\b"],
    },
    {
        "id": "apt",
        "label": "Nation-State",
        "blurb": "State-linked intrusion sets, espionage campaigns, and "
                 "attribution reporting.",
        "strong": [r"\bstate[- ](?:sponsored|linked|backed|aligned)\b",
                   r"\bnation[- ]state\b", r"\bAPT\d+\b", r"\bcyber ?espionage\b",
                   r"\b(?:Chinese|Russian|Iranian|North Korean|DPRK) (?:hackers|actors|group|state)\b"],
        "weak": [r"\bespionage\b", r"\battribut(?:ed|ion)\b", r"\bthreat actor\b",
                 r"\bintrusion set\b", r"\blazarus\b", r"\bkimsuky\b", r"\bsandworm\b",
                 r"\bfancy bear\b", r"\bvolt typhoon\b", r"\bsalt typhoon\b"],
    },
    {
        "id": "malware",
        "label": "Malware",
        "blurb": "Loaders, stealers, backdoors, botnets, and the tooling "
                 "behind campaigns.",
        "strong": [r"\bmalware\b", r"\b(?:info)?stealer\b", r"\bbackdoors?\b",
                   r"\btrojans?\b", r"\bbotnets?\b", r"\bloaders?\b", r"\brootkit\b",
                   r"\bwipers?\b"],
        "weak": [r"\bpayloads?\b", r"\bC2\b", r"\bcommand[- ]and[- ]control\b",
                 r"\bdroppers?\b", r"\bimplants?\b", r"\bcryptominers?\b", r"\bspyware\b"],
    },
    {
        "id": "phishing",
        "label": "Phishing & Fraud",
        "blurb": "Credential theft, social engineering, business email "
                 "compromise, and scam infrastructure.",
        "strong": [r"\bphish(?:ing|ed|ers)?\b", r"\bsmishing\b", r"\bvishing\b",
                   r"\bbusiness email compromise\b", r"\bBEC\b",
                   r"\bMFA (?:bypass|fatigue)\b"],
        "weak": [r"\bsocial engineering\b", r"\bcredential (?:theft|harvesting|stuffing)\b",
                 r"\bscams?\b", r"\bfraud\b", r"\bimpersonat", r"\bspoof(?:ed|ing)\b"],
    },
    {
        "id": "supplychain",
        "label": "Supply Chain",
        "blurb": "Compromise of packages, dependencies, build systems, and "
                 "third-party providers.",
        "strong": [r"\bsupply[- ]chain\b", r"\bnpm packages?\b", r"\bPyPI\b",
                   r"\bmalicious packages?\b", r"\bdependency confusion\b",
                   r"\btyposquat"],
        "weak": [r"\bthird[- ]party (?:provider|vendor|breach)\b", r"\bopen[- ]source\b",
                 r"\bmaintainers?\b", r"\bCI/CD\b", r"\bbuild pipeline\b", r"\bSBOM\b"],
    },
    {
        "id": "cloud",
        "label": "Cloud & Identity",
        "blurb": "Cloud misconfiguration, identity provider abuse, SaaS "
                 "tenancy, and container security.",
        "strong": [r"\bmisconfigur", r"\bS3 buckets?\b", r"\bAzure AD\b", r"\bEntra ID\b",
                   r"\bIAM (?:role|policy|misconfig)\b", r"\bkubernetes\b"],
        "weak": [r"\bcloud\b", r"\bAWS\b", r"\bAzure\b", r"\bGCP\b", r"\bSaaS\b",
                 r"\bcontainers?\b", r"\bOAuth\b", r"\bSSO\b", r"\bidentity provider\b"],
    },
    {
        "id": "policy",
        "label": "Policy & Regulation",
        "blurb": "Law, enforcement, sanctions, disclosure mandates, and "
                 "government advisories.",
        "strong": [r"\bsanction(?:s|ed|ing)\b", r"\bindict(?:ed|ment)\b",
                   r"\bregulat(?:ion|or|ory)\b", r"\bCISA (?:directive|advisory|adds)\b",
                   r"\bGDPR\b", r"\bfine[d]? \$?\d", r"\blawsuits?\b"],
        "weak": [r"\bgovernment\b", r"\bpolicy\b", r"\blegislation\b", r"\bcourts?\b",
                 r"\bDOJ\b", r"\bEuropol\b", r"\bFBI\b", r"\bNCSC\b", r"\bcompliance\b"],
    },
    {
        "id": "ai",
        "label": "AI Security",
        "blurb": "Attacks on and with machine-learning systems: prompt "
                 "injection, model abuse, and AI-assisted operations.",
        "strong": [r"\bprompt injection\b", r"\bjailbreak(?:ing)?\b",
                   r"\bLLM\b", r"\bAI[- ](?:generated|powered|assisted) (?:attack|malware|phishing)\b",
                   r"\bmodel poisoning\b"],
        "weak": [r"\bartificial intelligence\b", r"\bmachine learning\b",
                 r"\bchatbots?\b", r"\bdeepfakes?\b", r"\bgenerative AI\b"],
    },
]

# Compiled once at import.
for _t in TOPICS:
    _t["_strong"] = [re.compile(p, re.IGNORECASE) for p in _t["strong"]]
    _t["_weak"] = [re.compile(p, re.IGNORECASE) for p in _t["weak"]]

MAX_TOPICS_PER_STORY = 3


def classify(title: str, snippet: str = "") -> list[str]:
    """Return up to MAX_TOPICS_PER_STORY topic ids, most confident first.

    The title is weighted double: a headline states what a story is about,
    while a snippet often mentions adjacent things in passing. Scoring keeps
    a single incidental keyword from claiming the story.
    """
    title = title or ""
    snippet = snippet or ""
    scored: list[tuple[int, int, str]] = []

    for idx, topic in enumerate(TOPICS):
        score = 0
        for pat in topic["_strong"]:
            if pat.search(title):
                score += 6
            elif pat.search(snippet):
                score += 3
        for pat in topic["_weak"]:
            if pat.search(title):
                score += 2
            elif pat.search(snippet):
                score += 1

        # Threshold: one strong title hit, one strong snippet hit, or a
        # convergence of weak signals. A lone weak keyword scores 1-2 and
        # is discarded.
        if score >= 3:
            # idx breaks ties toward the more specific topic, since TOPICS
            # is ordered most-specific first.
            scored.append((-score, idx, topic["id"]))

    scored.sort()
    return [tid for _, _, tid in scored[:MAX_TOPICS_PER_STORY]]


def topic_meta() -> list[dict]:
    """Public topic list for templates -- no compiled patterns."""
    return [
        {"id": t["id"], "label": t["label"], "blurb": t["blurb"]}
        for t in TOPICS
    ]


def enrich(title: str, snippet: str) -> tuple[list[str], list[str]]:
    """Return (topic_ids, cve_ids) for one article."""
    cves = extract_cves(title, snippet)
    topics = classify(title, snippet)
    # A story carrying a CVE identifier is about a vulnerability by
    # definition, even if the headline uses none of the keyword vocabulary.
    if cves and "vuln" not in topics:
        topics = (["vuln"] + topics)[:MAX_TOPICS_PER_STORY]
    return topics, cves
