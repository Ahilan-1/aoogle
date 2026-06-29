# aoogle

A meta search engine that scrapes public web indexes and re-ranks results using a multi-factor scoring algorithm. No ads, no AI summaries, no tracking.

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
- Scoring is fully transparent and heuristic (no ML, no vectors, no indexing)

## API

Free, tokenless search API for agents, CLI tools, and LLMs. No registration or API key needed.

```
GET /api/search?q=your+query
```

- 25 requests per hour per IP address
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

The app is Flask-based and ready for any WSGI server. A `vercel.json` is included for Vercel deployment.

## Tech stack

- Python 3 + Flask
- BeautifulSoup for scraping
- DuckDuckGo HTML endpoint (web results)
- Bing Images (image results)
- Google Suggest API (autocomplete)
- In-memory caching (Redis optional)
- Chart.js (live stats dashboard)

## License

Apache 2.0
