"""Build Arlong's immutable search-safety and authority lookup database.

The source JSON files stay build-time inputs.  The web process opens only the
SQLite output, so Python never expands ~1.8 million domains into a set/dict in
production memory.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _normalise_domain(value: object) -> str:
    return str(value or '').strip().lower().removeprefix('www.').rstrip('.')


def build_database(blocklist_path: Path, tranco_path: Path, output_path: Path) -> dict:
    with blocklist_path.open('r', encoding='utf-8') as handle:
        blocklist_doc = json.load(handle)
    with tranco_path.open('r', encoding='utf-8') as handle:
        tranco_doc = json.load(handle)

    blocked = sorted({
        domain for domain in (
            _normalise_domain(value)
            for value in blocklist_doc.get('blocklist_domains', [])
        ) if domain
    })
    authority = sorted(
        (domain, float(score))
        for domain, score in (
            (_normalise_domain(key), value) for key, value in tranco_doc.items()
        ) if domain
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=output_path.name + '.', suffix='.tmp', dir=str(output_path.parent)
    )
    os.close(fd)
    temporary_path = Path(temporary_name)
    try:
        connection = sqlite3.connect(str(temporary_path))
        try:
            connection.executescript(
                """
                PRAGMA journal_mode = OFF;
                PRAGMA synchronous = OFF;
                PRAGMA temp_store = MEMORY;
                PRAGMA page_size = 4096;
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE blocked_domains (
                    domain TEXT PRIMARY KEY
                ) WITHOUT ROWID;
                CREATE TABLE domain_authority (
                    domain TEXT PRIMARY KEY,
                    score REAL NOT NULL
                ) WITHOUT ROWID;
                """
            )
            connection.executemany(
                'INSERT INTO blocked_domains(domain) VALUES (?)',
                ((domain,) for domain in blocked),
            )
            connection.executemany(
                'INSERT INTO domain_authority(domain, score) VALUES (?, ?)', authority
            )
            connection.executemany(
                'INSERT INTO metadata(key, value) VALUES (?, ?)',
                (
                    ('schema_version', '1'),
                    ('blocked_domains', str(len(blocked))),
                    ('authority_domains', str(len(authority))),
                ),
            )
            connection.commit()
            integrity = connection.execute('PRAGMA integrity_check').fetchone()[0]
            if integrity != 'ok':
                raise RuntimeError(f'SQLite integrity check failed: {integrity}')
            counts = {
                'blocked_domains': connection.execute(
                    'SELECT COUNT(*) FROM blocked_domains'
                ).fetchone()[0],
                'authority_domains': connection.execute(
                    'SELECT COUNT(*) FROM domain_authority'
                ).fetchone()[0],
            }
            if counts != {
                'blocked_domains': len(blocked),
                'authority_domains': len(authority),
            }:
                raise RuntimeError(f'Row-count verification failed: {counts}')
        finally:
            connection.close()
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return {
        'output': str(output_path),
        'blocked_domains': len(blocked),
        'authority_domains': len(authority),
        'bytes': output_path.stat().st_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--blocklist', type=Path, default=ROOT / 'blocklist_domains.json')
    parser.add_argument('--tranco', type=Path, default=ROOT / 'tranco_authority.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'search_intelligence.sqlite3')
    parser.add_argument(
        '--remove-sources', action='store_true',
        help='Remove the JSON build inputs only after the SQLite output verifies successfully.',
    )
    args = parser.parse_args()
    result = build_database(args.blocklist, args.tranco, args.output)
    if args.remove_sources:
        for source in {args.blocklist.resolve(), args.tranco.resolve()}:
            if source != args.output.resolve() and source.is_file():
                source.unlink()
        result['source_json_removed'] = True
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
