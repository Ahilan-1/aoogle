#!/usr/bin/env python3
"""Seed Postgres with the current data.json contents.

Usage (run once, or any time you want to re-sync):
    DATABASE_URL=postgresql://user:pass@host:5432/db  python scripts/pg_sync.py

Idempotent: upserts every top-level key into the app_data table and prints
per-key counts so you can verify against data.json before switching the app to
DATABASE_URL mode.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))
except ImportError:
    pass

import pg_db  # noqa: E402


def main():
    if not os.environ.get('DATABASE_URL'):
        print('ERROR: DATABASE_URL environment variable is not set')
        print('Example:  $env:DATABASE_URL="postgresql://user:pass@host:5432/db"')
        sys.exit(1)
    if not pg_db.enabled():
        print('ERROR: psycopg2 is not installed. Run: pip install psycopg2-binary')
        sys.exit(1)

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.environ.get('DATA_FILE') or os.path.join(base, 'data.json')
    if not os.path.exists(path):
        print(f'ERROR: data file not found: {path}')
        sys.exit(1)

    with open(path, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
    if not isinstance(data, dict):
        print('ERROR: data file does not contain a JSON object')
        sys.exit(1)

    print(f'Seeding {len(data)} top-level keys from {path}')
    if not pg_db.init_schema():
        print('ERROR: could not create schema / reach Postgres')
        sys.exit(1)
    if not pg_db.pg_save_all(data):
        print('ERROR: Postgres save failed')
        sys.exit(1)

    print('Seeded successfully. Per-key rows:')
    for k, v in data.items():
        if isinstance(v, (list, dict)):
            print(f'  {k}: {len(v)}')
        else:
            print(f'  {k}: {v!r}')
    print()
    print('Verify in psql with:  SELECT key, jsonb_array_length(value) FROM app_data;')
    print('(Only keys that are arrays/dicts have array lengths.)')


if __name__ == '__main__':
    main()
