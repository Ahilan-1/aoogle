import requests
from bs4 import BeautifulSoup

s = requests.Session()
h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# 1. WikiLeaks
print('=== WIKILEAKS ===')
r = s.post('https://search.wikileaks.org/', data={'query': 'test', 'exact_phrase': '', 'include_subfolders': '1'}, headers=h, timeout=10)
soup = BeautifulSoup(r.text, 'html.parser')
# Try to find result tables
tables = soup.find_all('table')
print(f'Tables: {len(tables)}')
for table in tables:
    rows = table.find_all('tr')
    print(f'  Table rows: {len(rows)}')
    for row in rows[:3]:
        print(f'    Row: {row.get_text(strip=True)[:80]}')
# Check for any tr with class containing "result"
for tr in soup.find_all('tr'):
    cls = tr.get('class', [])
    if any('result' in str(c).lower() for c in cls):
        print(f'  Result row class={cls}: {tr.get_text(strip=True)[:60]}')

print()

# 2. Torrentz2
print('=== TORRENTZ2 ===')
r = s.get('https://torrentz2.nz/search?q=test', headers=h, timeout=10)
soup = BeautifulSoup(r.text, 'html.parser')
dls = soup.find_all('dl')
print(f'DL elements: {len(dls)}')
for dl in dls[:3]:
    dt = dl.find('dt')
    if dt:
        a = dt.find('a')
        if a:
            print(f'  Title: {a.get_text(strip=True)[:60]} -> {a.get("href","?")[:60]}')
    dd = dl.find('dd')
    if dd:
        print(f'  Snippet: {dd.get_text(strip=True)[:100]}')

print()

# 3. Ahmia - check if search works
print('=== AHMIA ===')
r = s.get('https://ahmia.fi/search/?q=test', headers=h, timeout=10)
print(f'Status: {r.status_code}, URL: {r.url}, Length: {len(r.text)}')
# Save to file for inspection
with open('ahmia_test.html', 'w', encoding='utf-8') as f:
    f.write(r.text)
soup = BeautifulSoup(r.text, 'html.parser')
lis = soup.find_all('li', class_='result')
print(f'li.result elements: {len(lis)}')
if len(lis) == 0:
    # Try other selectors
    for sel in ['li', '.search-result', '.result', 'article']:
        items = soup.select(sel)
        print(f'  selector "{sel}": {len(items)}')
    # Show body text length and first 200 chars
    body = soup.find('body')
    if body:
        print(f'  Body text: {body.get_text(strip=True)[:300]}')
