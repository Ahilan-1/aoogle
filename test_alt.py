import requests
from bs4 import BeautifulSoup

s = requests.Session()
h = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

tests = [
    # Torrent sites
    ('TorrentGalaxy', 'https://torrentgalaxy.to/torrents.php?search=test'),
    ('Nyaa.si', 'https://nyaa.si/?q=test'),
    ('RARBG (rarbg.mx)', 'https://rarbg.mx/torrents.php?search=test'),
    ('LimeTorrents', 'https://www.limetorrents.lol/search/all/test/'),
    # Leak/dump sites
    ('S3 Leaks', 'https://s3leaks.com/search?q=test'),
    ('Intelligence X', 'https://intelx.io/?s=test'),
    # Data dumps
    ('DataBreachForums', 'https://breached.surf/search?q=test'),
]

for name, url in tests:
    try:
        r = s.get(url, headers=h, timeout=10, allow_redirects=True)
        print(f'{name}: status={r.status_code}, len={len(r.text)}, url={r.url}')
        if r.status_code == 200 and len(r.text) > 500:
            soup = BeautifulSoup(r.text, 'html.parser')
            links = soup.find_all('a', href=True)
            txt_links = [(a.get_text(strip=True)[:50], a['href'][:80]) for a in links if a.get_text(strip=True)]
            print(f'  Links with text: {len(txt_links)}')
            if txt_links:
                for t, href in txt_links[:3]:
                    print(f'    [{t}] -> {href}')
        print()
    except Exception as e:
        print(f'{name}: ERROR - {str(e)[:80]}\n')
