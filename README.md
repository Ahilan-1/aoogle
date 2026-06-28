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

## License

Apache 2.0
