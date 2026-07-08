import urllib.request, json, sys, time

BASE = 'http://127.0.0.1:5000'

tests = [
    ('SPORTS', '/api/news?category=sports'),
    ('GAMING', '/api/news?category=gaming'),
    ('ASIAN', '/api/news?category=asian'),
    ('SCORES', '/api/scores'),
]

for name, path in tests:
    try:
        r = urllib.request.urlopen(BASE + path, timeout=15)
        d = json.loads(r.read())
        if 'items' in d:
            items = d['items']
            imgs = sum(1 for i in items if i.get('image'))
            print(f'{name}: ok={d.get("ok")} items={len(items)} with_imgs={imgs}')
            if items and items[0].get('image'):
                print(f'  first img: {items[0]["image"][:80]}')
        else:
            print(f'{name}: ok={d.get("ok")} matches={len(d.get("items",[]))}')
    except Exception as e:
        print(f'{name}: ERROR - {e}')
