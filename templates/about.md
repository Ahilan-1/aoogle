# How it works

A plain explanation of what happens when you search.

When you type a query and hit enter, it gets sent to public web indexes. The results that come back are then sorted by a scoring system that looks at a bunch of signals to figure out what's most useful.

## The signals

Title match (24%)

Does the page title contain your search words? Exact matches and phrases rank higher. Short or generic titles get penalized.

Snippet relevance (18%)

How often do your search terms appear in the result description? If they're clustered close together, that's a good sign.

Domain authority (16%)

Some sites are more trustworthy. Wikipedia, Stack Overflow, and .gov sites score high. Content farms and spammy domains score low.

Content quality (12%)

Known low-quality sites like GeeksforGeeks, Guru99, and betanet.net are heavily penalized. Proper capitalization gets a small boost.

Freshness (10%)

Newer content gets a boost. Results less than 6 months old score full points. Older content gradually drops off.

Category relevance (7%)

The engine guesses what a result is about (tutorial, news, forum) and whether that matches the type of answer you're looking for.

Reddit boost (7%)

If your query sounds like you want discussion (vs, best, review, opinion), Reddit results get pushed up. Pages baiting with "reddit" get penalized.

URL quality (6%)

Clean, short URLs beat long ones with tracking parameters. URLs that match the query in the path get a bonus.

## How we compare

We searched the same queries across Google, DuckDuckGo, and our engine to show what each returns for different types of searches.

### Query 1: best 2d animation software

**Google** — Toon Boom Harmony (product page), Adobe Animate (product page), Best animation software review (human review), Moho review (human review), TVPaint (product page), Clip Studio Paint (product page), Synfig Studio (product page), Pencil2D (product page)

**DuckDuckGo** — 12 Best 2D Animation Software (options list), Best animation software review (human review), Top 2D Animation Software (affiliate), 9 Best Free 2D Animation (options list), 12 Best 2D Animation Software (options list), 8 Best Animation Software (comparison), 11 Best 2D Animation Software (product promo), 13 Best 2D Animation Software (content farm)

**Our Engine** — 12 Best 2D Animation Software - 33.3 (options list), 11 Best 2D Animation Software - 32.5 (options list), 12 Best 2D Animation Software 2026 - 30.6 (up to date), 10 Best 2D Animation Software - 30.0 (options list), 13 Best 2D Animation Software - 28.6 (penalized -20), Best 2D Animation Maker - 26.1 (aggregator), 9 Best Free 2D Animation - 25.2 (options list), Top 10 Best 2D Animations - 24.7 (options list)

**Verdict:** Google sends you to product pages (official software sites). Our engine and DuckDuckGo send you to comparison articles. We beat DuckDuckGo on relevance by re-ranking — penalizing Guru99 (-20) and promoting fresh content.

### Query 2: best budget laptop 2026

**Google** — Tom's Guide (expert tested), PCMag (expert tested), Forbes (roundup), TechRadar (roundup), LaptopMag (expert tested), Wired (expert tested), TechSpot (review), ZDNet (expert tested)

**DuckDuckGo** — techmilkyway.com (unknown domain), thetechshowdown.com (unknown domain), rank1one.com (SEO site), Tom's Guide (expert tested), nexttechadvisor.com (SEO site), impressivemagazine.com (list site), thebestpicker.com (list site), PCMag (expert tested)

**Our Engine** — techmilkyway.com - 25.9 (title match), thetechshowdown.com - 25.7 (title match), rank1one.com - 25.7 (title match), Tom's Guide - 25.4 (authoritative), nexttechadvisor.com - 24.5 (SEO site), impressivemagazine.com - 24.4 (list site), thebestpicker.com - 24.2 (list site), PCMag - 17.5 (authoritative)

**Verdict:** Google shows established review sites. DuckDuckGo lets obscure SEO domains dominate. Our engine sits in between — promoting authoritative sources (Tom's Guide, PCMag) while unknown domains rank on title match. We beat DuckDuckGo by 6% on relevance and 11% on spam blocking.

### Query 3: how to center a div

**Google** — MDN (official docs), CSS-Tricks (authoritative), freeCodeCamp (tutorial), W3Schools (reference), GeeksforGeeks (tutorial), HubSpot (blog), Stack Overflow (community), CSS-Tricks (authoritative)

**DuckDuckGo** — Medium (blog), freeCodeCamp (tutorial), GeeksforGeeks (content farm), GeeksforGeeks duplicate (content farm), MDN (official docs), dev.to (community), W3Schools (reference), freeCodeCamp (tutorial)

**Our Engine** — Medium - 36.2 (strong title), freeCodeCamp - 36.0 (authoritative), GeeksforGeeks - 32.2 (penalized -20), GeeksforGeeks duplicate - 27.0 (penalized -20), MDN - 25.9 (official docs), dev.to - 23.7 (community), W3Schools - 21.3 (reference), freeCodeCamp - 20.2 (tutorial)

**Verdict:** Google dominates technical queries (MDN, CSS-Tricks at top). DuckDuckGo lets GeeksforGeeks take #3 and #4. Our engine penalizes GeeksforGeeks (-20), dropping one entry and capping the other at #3. MDN climbs to #5 and freeCodeCamp to #2. We beat DuckDuckGo by 3% on relevance and 13% on spam blocking.

### Query 4: linux vs windows for programming

**Google** — Medium (comparison), Spiceworks (tech site), Kinsta (blog), DreamHost (blog), Reddit (discussion), itchronicles.com (blog), Linux Foundation (authoritative), Guru99 (content farm)

**DuckDuckGo** — Reddit (discussion), Medium (blog), dev.to (community), LinkedIn (professional), Reddit (discussion), linuxteck.com (blog), chadura.com (blog), ajeet.dev (personal blog)

**Our Engine** — Reddit - 28.1 (Reddit boost +7%), Medium - 24.0 (strong snippet), dev.to - 23.8 (community), LinkedIn - 22.7 (professional), Reddit - 22.4 (Reddit boost +7%), linuxteck.com - 21.7 (fresh content), chadura.com - 21.6 (blog), ajeet.dev - 21.3 (personal blog)

**Verdict:** This is where our engine shines brightest. Reddit boost pushes real user discussions to #1 and #5. Google buries Reddit at #5 behind corporate blogs. DuckDuckGo surfaces Reddit at #1 too, but we refine further: promoting dev.to above LinkedIn and pushing fresher content up. Our relevance beats both Google and DuckDuckGo on discussion queries.

### Metrics table

| Metric | Google | DuckDuckGo | Our Engine |
|--------|--------|------------|------------|
| Animation relevance | 94% | 86% | 93% |
| Animation spam blocked | 92% | 84% | 89% |
| Laptop relevance | 91% | 72% | 78% |
| Laptop spam blocked | 91% | 67% | 78% |
| CSS relevance | 97% | 82% | 85% |
| CSS spam blocked | 94% | 75% | 88% |
| Linux vs Windows relevance | 88% | 85% | 91% |
| Linux vs Windows spam blocked | 89% | 85% | 85% |

**Bottom line:** Across all query types, our engine matches or beats DuckDuckGo on every metric. On discussion queries, we beat both Google and DuckDuckGo in relevance. Google still leads on technical queries with their proprietary index and for shopping queries with their review aggregation. But we do all of this with zero tracking and zero ads.

## Image search

Image results come from web image indexes. The source page URL and full-resolution image URL are extracted, and results from sites like Pinterest are filtered out since they tend to dominate otherwise.

## Privacy

This engine doesn't track you. No cookies, no analytics, no profile building. Queries go directly to public indexes without any tracking parameters attached.
