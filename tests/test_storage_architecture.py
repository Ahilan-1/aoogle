import json
import sqlite3

import pytest

import main
from scripts.build_search_intelligence_db import build_database


def test_search_intelligence_build_is_lossless_normalized_and_read_only(tmp_path):
    blocklist = tmp_path / 'blocklist.json'
    tranco = tmp_path / 'tranco.json'
    output = tmp_path / 'search.sqlite3'
    blocklist.write_text(json.dumps({
        'blocklist_domains': ['WWW.Bad.Example.', 'bad.example', 'other.test'],
    }), encoding='utf-8')
    tranco.write_text(json.dumps({
        'WWW.Good.Example.': 0.91,
        'news.test': 0.42,
    }), encoding='utf-8')

    result = build_database(blocklist, tranco, output)
    assert result['blocked_domains'] == 2
    assert result['authority_domains'] == 2

    index = main.SearchIntelligenceIndex(output)
    assert index.available is True
    assert index.is_blocked('bad.example') is True
    assert index.is_blocked('good.example') is False
    assert index.authority('good.example') == pytest.approx(0.91)

    connection = sqlite3.connect(
        'file:' + str(output).replace('\\', '/') + '?mode=ro', uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("INSERT INTO blocked_domains VALUES ('write.test')")
    finally:
        connection.close()


def test_postgres_write_rejects_disappearing_protected_fields(monkeypatch):
    monkeypatch.setattr(main, 'PERSISTENCE_BACKEND', 'postgres')
    monkeypatch.setattr(main, 'DATABASE_URL', 'postgresql://configured')
    monkeypatch.setattr(main.pg_db, 'enabled', lambda: True)
    monkeypatch.setattr(main.pg_db, 'pg_load_all', lambda: {
        'users': {'u1': {'username': 'safe'}},
        'reports': [],
    })
    saved = []
    monkeypatch.setattr(main.pg_db, 'pg_save_all', lambda data: saved.append(data) or True)

    with pytest.raises(ValueError, match='users'):
        main._save_json({'reports': []})
    assert saved == []


def test_postgres_failure_never_falls_back_to_json_write(monkeypatch, tmp_path):
    legacy = tmp_path / 'data.json'
    legacy.write_text('{"unchanged": true}', encoding='utf-8')
    monkeypatch.setattr(main, 'DATA_FILE', str(legacy))
    monkeypatch.setattr(main, 'PERSISTENCE_BACKEND', 'postgres')
    monkeypatch.setattr(main, 'DATABASE_URL', 'postgresql://configured')
    monkeypatch.setattr(main.pg_db, 'enabled', lambda: True)
    monkeypatch.setattr(main.pg_db, 'pg_load_all', lambda: {'reports': []})
    monkeypatch.setattr(main.pg_db, 'pg_save_all', lambda data: False)

    with pytest.raises(main.PersistenceUnavailableError):
        main._save_json({'reports': [{'id': 1}]})
    assert legacy.read_text(encoding='utf-8') == '{"unchanged": true}'
