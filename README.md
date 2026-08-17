# aoogle

A meta search engine that scrapes public web indexes and re-ranks results using a multi-factor scoring algorithm. No ads, no promoted links, no user tracking. AI features (chat at `/ai` and the optional search "AI Summary" button) are opt-in and never run by default.

## How it works

1. Your query is sent to public web indexes
2. Results are scored across 8 signals:
   - **Title match** (24%) — exact phrase matches rank highest
   - **Snippet relevance** (18%) — term frequency and proximity
   - **Domain authority** (16%) — trusted sites score higher, content farms get penalized
   - **Content quality** (12%) — known low-quality sites (GeeksforGeeks, Guru99) hit with −20
   - **Freshness** (10%) — newer content gets a boost
   - **Category relevance** (7%) — does the result type match your intent?
   - **Reddit boost** (7%) — discussion queries push Reddit results up
   - **URL quality** (6%) — clean short URLs beat tracking-laden ones
3. Results are sorted by total score and returned — no promoted links, no sponsored slots

## Features

- Clean, familiar search interface
- Image search via Bing
- Knowledge panels for popular entities
- Search suggestions (powered by Google Suggest API)
- "I'm Feeling Lucky" — random wholesome query
- Domain sitelinks — repeated hits from the same root domain collapse into a single parent card with indented child links
- Opt-in AI Summary button on results plus a dedicated AI chat at `/ai`
- Scoring is fully transparent and heuristic (no ML, no vectors, no indexing)

## API

Public search API for agents, CLI tools, and LLM integrations.

```
GET /api/search?q=your+query
```

Two access tiers:

- **Tokenless** — 2 requests per hour per IP address. For occasional, exploratory use.
- **Registered** — create a free account, accept the [Terms of Service](https://arlong.org/terms-of-service), and get an API key with a burst limit of **80 requests per 30 minutes** and a Free allowance of **100 API/MCP requests per month**. Founder and Pro include 2,000 per billing period. Keys and usage live at [`/api/dashboard`](https://arlong.org/api/dashboard).

Pass your key via the `Authorization` header (`Authorization: Bearer al_...`) or the `key` query parameter.

The hosted MCP endpoint at `/mcp` also supports OAuth 2.1 with Google sign-in.
Compatible MCP clients discover authorization through
`/.well-known/oauth-protected-resource`; API-key authentication remains supported.

MCP search profiles are explicit so agents can control latency and context use:

- `arlong_quick` — plain links only; no extraction or AI evaluation (1 credit)
- `arlong_search` — balanced semantic relevance, trust signals, and previews (1 credit)
- `arlong_deep` — parallel extraction and corroboration across up to 20 sources (2 credits)
- `arlong_extract` — clean text from one public URL (1 credit)
- `arlong_answer` — grounded cited synthesis (3 credits)
- `arlong_status` — capabilities and live health (free)

- Returns clean JSON with title, url, snippet, category, score, and more
- Supports pagination (`&page=N`) and pretty-print (`&pretty=1`)
- Respects crisis detection and content moderation

**Documentation:** [`/docs`](https://aoogle-production.up.railway.app/docs)

**Quick start:**
```bash
curl "https://aoogle-production.up.railway.app/api/search?q=python+programming"
```

Agent helper, interactive CLI demo, and JavaScript/Node.js examples available on the docs page.

## Running locally

```bash
pip install -r requirements.txt
python main.py
```

The server runs on `http://localhost:5000`.

## Deployment

The app is Flask-based and ready for any WSGI server. A `railway.json` is included for Railway deployment.

## Tech stack

- Python 3 + Flask
- BeautifulSoup for scraping
- DuckDuckGo HTML endpoint (web results)
- Bing Images (image results)
- Google Suggest API (autocomplete fallback)
- In-memory caching (Redis optional)
- Chart.js (live stats dashboard)

## License

**All rights reserved.** Arlong is proprietary and closed source. The source
code is private and not distributed. You may not copy, modify, redistribute,
or run a derivative service from it without prior written consent from Arlong.
See the [Terms of Service](https://aoogle-production.up.railway.app/terms-of-service).
