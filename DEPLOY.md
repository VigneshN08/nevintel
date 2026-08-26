# Deploy NEVINTEL

About five minutes. You need a GitHub account and `git`.

---

## 1. Set your details

From inside this folder, replace the three placeholders. Pick a real email you
actually read — it is the takedown address, and it is the cheapest insurance
this project has.

```bash
GH_USER="your-github-username"
EMAIL="you@example.com"
REPO="nevintel"

grep -rl 'VigneshN08\|nemmikantivignesh17@gmail.com' --exclude-dir=.git . \
  | xargs sed -i '' -e "s|VigneshN08|$GH_USER|g" -e "s|nemmikantivignesh17@gmail.com|$EMAIL|g"   # macOS
# Linux: drop the '' after -i
```

Then set the repo name in `hugo.toml` if you chose something other than
`nevintel`:

```bash
sed -i '' "s|/nevintel/|/$REPO/|g" hugo.toml
```

Check it took:

```bash
grep -rn "VigneshN08\|nemmikantivignesh17@gmail.com" --exclude-dir=.git .   # should print nothing
```

---

## 2. Create the repo and push

**Keep it public.** This is not about openness — public repos get unlimited
free GitHub Actions minutes on standard runners. Private repos get 2,000 a
month, which across 360 builds leaves 5.5 minutes each. Public is the
difference between this working and not.

With the `gh` CLI:

```bash
git init -b main
git add -A
git commit -m "NEVINTEL: initial"
gh repo create "$REPO" --public --source=. --push
```

Without `gh` — create the repo at <https://github.com/new> (public, no README,
no .gitignore, no licence), then:

```bash
git init -b main
git add -A
git commit -m "NEVINTEL: initial"
git remote add origin "https://github.com/$GH_USER/$REPO.git"
git push -u origin main
```

---

## 3. Turn on Pages and Actions

1. **Settings → Pages → Source: GitHub Actions.** Not "Deploy from a branch".
2. **Settings → Actions → General → Workflow permissions:**
   select **Read and write permissions**. The build commits the refreshed
   corpus back to the repo, and without this the push step fails.

---

## 4. First run

**Actions → build → Run workflow.**

Roughly 2–4 minutes. It fetches every feed, sanitises and stores what it finds,
tags topics and CVEs, builds the site, indexes search, commits the corpus, and
deploys.

Your site: `https://<your-username>.github.io/<repo>/`

From then on it rebuilds on its own at 37 minutes past every second hour.

### If the first run is disappointing

Normal, and worth understanding rather than fixing. Most feeds only expose
5–50 items, and *The Record* exposes 5. The first build captures a snapshot,
not an archive — the corpus fills out over the following days and the site gets
better on its own. The `/sources/` page shows exactly what each feed returned.

A source showing `http_error` is usually a publisher blocking datacenter
traffic (BleepingComputer does this), not an outage. The fetcher retries once
with a browser user-agent and logs the result either way. One bad feed never
fails the build. Every feed failing does — deliberately, so the site cannot go
quietly stale for weeks.

---

## 5. Worth doing soon

**Put Cloudflare in front** (free plan, proxied DNS). GitHub Pages has a
100 GB/month soft bandwidth limit and cannot set response headers; Cloudflare
fixes both and lets you set a Content-Security-Policy. Pagefind needs
`script-src 'wasm-unsafe-eval'` in that policy.

**Hardware 2FA on your registrar, DNS and Cloudflare accounts, separately.**
Whoever controls the DNS record controls what every visitor executes. No amount
of code review catches that, and it is a bigger risk than anything in this
codebase.

**Turn on email signup.** Set `subscribeEndpoint` in `hugo.toml` to a
Buttondown, Listmonk or Formspree URL. Until you do, both subscribe forms
render disabled with an explanation — a static site has no server to receive a
POST, and a form that silently drops addresses is worse than no form, because
people believe they subscribed.

**Watch three thresholds** as the archive grows: ~20,000 pages (fine on GitHub
Pages, would break Cloudflare Pages' file cap), ~250,000 pages (Pagefind stops
being viable — migrate to self-hosted Meilisearch on a small VPS), and 1 GB
(GitHub Pages' published-site cap — migrate to Cloudflare R2 with a Worker).

---

## Local development

```bash
pip install -r pipeline/requirements.txt

python pipeline/selftest.py     # 49 offline checks — run before any edit to sanitize.py
python pipeline/fetch.py        # pull feeds into corpus/corpus.db
python pipeline/render.py       # corpus -> content/story/*.md + data/site.json
hugo server                     # http://localhost:1313
```

After editing topic rules in `pipeline/enrich.py`, re-tag the existing corpus
so old stories pick up the new rule:

```bash
python pipeline/reenrich.py
```

To reproduce the CI build exactly:

```bash
hugo --minify --gc && npx pagefind@1.3.0 --site public
```

---

## Before you add a source

Check its licence first. **Ad-supported counts as commercial**, so every
"non-commercial use only" clause applies to this site. If in doubt, set
`snippet_words = 0` in `pipeline/sources.toml` and show headline and link only
— that is what SANS ISC gets, because its feed items are CC BY-NC.

The 25-word default cap is not arbitrary. *AP v. Meltwater* (S.D.N.Y. 2013)
held that reproducing an article's opening paragraph is **not** fair use even
with attribution and a link — and the opening paragraph is exactly what most
RSS `<description>` fields hand you. `README.md` has the full reasoning.
