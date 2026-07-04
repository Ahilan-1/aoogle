import requests
from bs4 import BeautifulSoup

s = requests.Session()
h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# Check WikiLeaks GET vs POST
print('=== WIKILEAKS GET ===')
r = s.get('https://search.wikileaks.org/', params={'query': 'test', 'include_subfolders': '1'}, headers=h, timeout=10)
print(f'Status: {r.status_code}, URL: {r.url}, Length: {len(r.text)}')
soup = BeautifulSoup(r.text, 'html.parser')
# Search for any link elements
for a in soup.find_all('a', href=True)[:20]:
    txt = a.get_text(strip=True)[:60]
    href = a['href'][:100]
    if txt:
        print(f'  [{txt}] -> {href}')

print()
print('=== WIKILEAKS POST ===')
r = s.post('https://search.wikileaks.org/', data={'query': 'test', 'exact_phrase': '', 'include_subfolders': '1'}, headers=h, timeout=10)
print(f'Status: {r.status_code}, URL: {r.url}, Length: {len(r.text)}')
soup = BeautifulSoup(r.text, 'html.parser')
for a in soup.find_all('a', href=True)[:20]:
    txt = a.get_text(strip=True)[:60]
    href = a['href'][:100]
    if txt and len(txt) > 10:
        print(f'  [{txt}] -> {href}')
