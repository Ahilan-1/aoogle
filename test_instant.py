import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from main import get_weather_panel, get_definition_panel, get_info_box
import json

print('=== WEATHER TESTS ===')
for q in ['weather in London', 'Tokyo weather', 'temperature in Paris', 'forecast New York', 'weather', 'weather in Chennai']:
    p = get_weather_panel(q)
    if p:
        print(f'  [{q}] -> {p["title"]}: {p["temp"]}, {p["condition"]}, facts={len(p.get("facts",[]))}')
    else:
        print(f'  [{q}] -> None')

print()
print('=== DEFINITION TESTS ===')
for q in ['define serendipity', 'hello definition', 'what does ephemeral mean', 'meaning of love', 'what is the definition of code']:
    p = get_definition_panel(q)
    if p:
        print(f'  [{q}] -> {p["title"]} ({p["type"]}): {p["description"][:80]}...')
    else:
        print(f'  [{q}] -> None')

print()
print('=== INFO BOX DISPATCH ===')
for q in ['weather in London', 'define serendipity', 'python programming', 'asdfghjklxyz']:
    p = get_info_box(q)
    if p:
        pt = p.get('panel_type', 'wikipedia')
        print(f'  [{q}] -> type={pt}, title={p.get("title","?")}')
    else:
        print(f'  [{q}] -> None')
