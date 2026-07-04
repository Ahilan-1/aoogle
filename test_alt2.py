import requests
from bs4 import BeautifulSoup

s = requests.Session()
h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# Nyaa.si structure
print('=== NYAA.SI ===')
r = s.get('https://nyaa.si/?q=test&s=seeders&o=desc', timeout=10)
soup = BeautifulSoup(r.text, 'html.parser')
# Check table structure
table = soup.find('table', class_='torrent-list')
if table:
    rows = table.find_all('tr')
    print(f'Table rows: {len(rows)}')
    for row in rows[1:4]:  # skip header
        tds = row.find_all('td')
        print(f'  TDs: {len(tds)}')
        for i, td in enumerate(tds):
            a = td.find('a')
            if a and a.get('href'):
                print(f'    td[{i}]: {a.get_text(strip=True)[:50]} -> {a["href"][:60]}')
            else:
                txt = td.get_text(strip=True)[:30]
                if txt:
                    print(f'    td[{i}]: {txt}')
else:
    print('No torrent-list table found')
    for t in soup.find_all('table'):
        print(f'Table class={t.get("class")}, rows={len(t.find_all("tr"))}')

print()

# Intelligence X structure
print('=== INTELX.IO ===')
r = s.get('https://intelx.io/?s=test', timeout=10)
print(f'Status: {r.status_code}, URL: {r.url}')
soup = BeautifulSoup(r.text, 'html.parser')
# Check for result elements
for cls in ['result', 'item', 'card', 'search-result', 'hit']:
    items = soup.find_all(class_=cls)
    print(f'  class "{cls}": {len(items)}')

# Check script tags for data
for script in soup.find_all('script'):
    if script.string and 'results' in script.string.lower():
        print(f'  Script with results: {script.string[:200]}...')
        break

# Look for any div with id containing 'result'
for div in soup.find_all('div', id=lambda x: x and 'result' in x.lower()):
    print(f'  div#{div.get("id")}: {div.get_text(strip=True)[:100]}')

print()

# LimeTorrents structure  
print('=== LIMETORRENTS ===')
r = s.get('https://www.limetorrents.fun/search/all/test/', timeout=10)
soup = BeautifulSoup(r.text, 'html.parser')
for cls in ['table', 'torrent', 'item']:
    items = soup.find_all(class_=cls)
    print(f'  class "{cls}": {len(items)}')
tables = soup.find_all('table')
print(f'  Tables: {len(tables)}')
for table in tables[:2]:
    rows = table.find_all('tr')
    print(f'  Table rows: {len(rows)}')
    for row in rows[1:3]:
        a = row.find('a', href=True)
        if a and a.get_text(strip=True):
            print(f'    [{a.get_text(strip=True)[:50]}] -> {a["href"][:60]}')
