import requests, time, json

q = 'market'
base = 'http://127.0.0.1:5000'

# Initial request
r = requests.get(f'{base}/poneglyph?q={q}', timeout=5)
print(f'Initial: status={r.status_code}, len={len(r.text)}')
print(f'pg-loading in response: {"pg-loading" in r.text}')
print(f'results in response: {"results" not in r.text or "No deep results" in r.text}')

# Poll progress
for i in range(15):
    r = requests.get(f'{base}/api/poneglyph-progress?q={q}', timeout=5)
    data = r.json()
    status = data.get('status', '?')
    found = data.get('found', 0)
    completed = data.get('sources_completed', 0)
    total = data.get('total_sources', 0)
    print(f'Poll {i}: status={status}, found={found}, completed={completed}/{total}')
    
    if status == 'done':
        results = data.get('results', [])
        print(f'\nDONE! Total results: {len(results)}')
        for res in results[:5]:
            print(f'  [{res.get("category","?")}] {res.get("title","?")[:80]}')
            print(f'       {res.get("url","")[:80]}')
        break
    time.sleep(3)
else:
    print('\nTimed out - checking recent logs...')
    try:
        with open('search_engine.log') as f:
            lines = f.readlines()
            for l in lines[-30:]:
                print(l.strip())
    except:
        print('No log file')
