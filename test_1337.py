import requests
h = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Referer': 'https://1337x.to/',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}
s = requests.Session()
s.headers.update(h)

# First visit homepage to get cookies
r1 = s.get('https://1337x.to/', timeout=10)
print(f'Homepage: status={r1.status_code}, cookies={dict(s.cookies)}, len={len(r1.text)}')

# Then search
r2 = s.get('https://1337x.to/search/test/1/', timeout=10)
print(f'Search: status={r2.status_code}, len={len(r2.text)}, url={r2.url}')
if r2.status_code != 200:
    # Try with alternative path
    r3 = s.get('https://1337x.to/category-search/test/Torrents/1/', timeout=10)
    print(f'Alt search: status={r3.status_code}, len={len(r3.text)}')
