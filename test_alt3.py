import requests, json
from bs4 import BeautifulSoup

s = requests.Session()
h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# Try IntelX API or different search path
print('=== INTELX SEARCH ===')

# Try the search API
r = s.post('https://intelx.io/search', 
    data={'term': 'test', 'target': 0, 'sort': 0, 'limit': 10},
    headers={**h, 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/x-www-form-urlencoded'},
    timeout=10)
print(f'Search API: status={r.status_code}, len={len(r.text)}')
try:
    d = r.json()
    print(f'JSON keys: {list(d.keys())}')
    if 'data' in d:
        print(f'Data items: {len(d["data"])}')
        for item in d['data'][:2]:
            print(json.dumps(item, indent=2)[:200])
except:
    print(f'Response preview: {r.text[:500]}')

# Try Nyaa.si with a more general category
print()
print('=== NYAA.SI (ALL CATEGORIES) ===')
r = s.get('https://nyaa.si/?q=leak&c=0_0&s=seeders&o=desc', timeout=10)
soup = BeautifulSoup(r.text, 'html.parser')
table = soup.find('table', class_='torrent-list')
if table:
    rows = table.find_all('tr')[1:]
    print(f'Total results: {len(rows)}')
    for row in rows[:3]:
        tds = row.find_all('td')
        if len(tds) >= 6:
            a = tds[1].find('a')
            title = a.get_text(strip=True)[:60] if a else '?'
            href = a['href'] if a and a.get('href') else '?'
            size = tds[3].get_text(strip=True) if len(tds) > 3 else '?'
            seeds = tds[5].get_text(strip=True) if len(tds) > 5 else '?'
            print(f'  [{title}] size={size} seeds={seeds} -> {href[:60]}')
