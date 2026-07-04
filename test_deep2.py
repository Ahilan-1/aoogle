import main, time, threading

engine = main.ImprovedSearch()
results, status = engine.search_poneglyph_deep('market')
print('Status:', status)

if status == 'running':
    for i in range(25):
        with main.pg_deep_lock:
            p = dict(main.pg_deep_progress.get('market', {}))
        s = p.get('status', '?')
        f = p.get('found', 0)
        c = p.get('sources_completed', 0)
        t = p.get('total_sources', 0)
        print(f'Poll {i}: status={s}, found={f}, completed={c}/{t}')
        
        if s == 'done':
            if f > 0:
                print('\nRESULTS FOUND!')
                for r in p.get('results', [])[:5]:
                    print(f'  [{r.get("category","?")}] {r.get("title","?")[:70]}')
                    print(f'    {r.get("url","")[:80]}')
            else:
                print('\nNo results found')
                print('Recent log lines:')
                try:
                    with open('search_engine.log') as log:
                        lines = log.readlines()
                        for l in lines[-15:]:
                            print(l.strip())
                except:
                    pass
            break
        time.sleep(3)
    else:
        print('Timed out')
