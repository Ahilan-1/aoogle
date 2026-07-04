import main, time

engine = main.ImprovedSearch()
results, status = engine.search_poneglyph_deep('confidential')
print('Status:', status)

if status == 'running':
    for i in range(30):
        with main.pg_deep_lock:
            p = dict(main.pg_deep_progress.get('confidential', {}))
        s = p.get('status', '?')
        f = p.get('found', 0)
        c = p.get('sources_completed', 0)
        t = p.get('total_sources', 0)
        sources_done = []
        if p.get('results'):
            cats = set(r.get('category','?') for r in p['results'])
            sources_done = list(cats)
        print(f'Poll {i}: status={s}, found={f}, completed={c}/{t}, categories={sources_done}')
        
        if s == 'done':
            if f > 0:
                print(f'\nFOUND {f} DEEP WEB RESULTS!')
                for r in p.get('results', [])[:5]:
                    print(f'  [{r.get("category","?")}] {r.get("title","?")[:80]}')
                    print(f'    {r.get("url","")[:100]}')
            else:
                print('\nNo deep web results - checking logs...')
                try:
                    with open('search_engine.log') as log:
                        lines = log.readlines()
                        for l in lines[-20:]:
                            if 'PG Deep' in l:
                                print(l.strip())
                except:
                    pass
            break
        time.sleep(3)
    else:
        print('Timed out')
