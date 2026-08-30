"""Authoritative PostgreSQL persistence for Arlong application state.

The first production migration imports every top-level key from the legacy
JSON document into an ``app_data`` JSONB row. Writes are transactional and
replace the complete logical document without dual-writing a mutable file.
This lossless intermediate schema prevents account, billing, OAuth, history,
or analytics fields from disappearing while those domains are normalized into
dedicated tables over time.
"""

import json
import os
import threading
import time
import logging

log = logging.getLogger(__name__)

try:
    import psycopg2
    import psycopg2.pool
    from psycopg2 import extras as _pg_extras
    _HAS_PSYCOPG2 = True
except Exception:  # pragma: no cover - depends on environment
    _HAS_PSYCOPG2 = False

_pool = None
_pool_lock = threading.Lock()
_schema_ready = False
_schema_lock = threading.Lock()
_last_save_ok = None  # None=unknown, True/False = result of last authoritative write


def _dsn():
    return os.environ.get('DATABASE_URL', '').strip()


def _safe_dsn():
    """Return the DSN with any password masked, for log lines."""
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(_dsn())
        netloc = parts.netloc
        if '@' in netloc:
            userinfo, host = netloc.rsplit('@', 1)
            if ':' in userinfo:
                userinfo = userinfo.split(':', 1)[0] + ':****'
            netloc = userinfo + '@' + host
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return '<database-url>'


def enabled():
    """True when the authoritative PostgreSQL backend is configured."""
    return bool(_dsn() and _HAS_PSYCOPG2)


def _sslmode():
    return os.environ.get('PGSSLMODE', 'require').strip() or 'require'


def _get_pool():
    global _pool
    if not enabled():
        return None
    with _pool_lock:
        if _pool is None:
            try:
                # Gunicorn runs one process with eight request threads. Use
                # psycopg2's synchronized pool; SimpleConnectionPool is not
                # safe to share across those threads.
                _pool = psycopg2.pool.ThreadedConnectionPool(
                    1, 5, _dsn(), sslmode=_sslmode(), connect_timeout=5,
                )
            except Exception as e:
                _pool = None
                log.error("PG pool init failed for %s: %s", _safe_dsn(), e)
        return _pool


def init_schema():
    """Create the app_data table if it does not exist (idempotent)."""
    global _schema_ready
    pool = _get_pool()
    if pool is None:
        return False
    with _schema_lock:
        if _schema_ready:
            return True
        conn = None
        try:
            conn = pool.getconn()
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS app_data ("
                    " key TEXT PRIMARY KEY,"
                    " value JSONB NOT NULL,"
                    " updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
                    ")"
                )
            conn.commit()
            _schema_ready = True
            return True
        except Exception as e:
            try:
                if conn is not None:
                    conn.rollback()
            except Exception:
                pass
            log.error("PG init_schema failed: %s", e)
            return False
        finally:
            if conn is not None:
                pool.putconn(conn)


def _release(pool, conn):
    try:
        if conn is not None:
            pool.putconn(conn)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def pg_load_all():
    """Return {top_level_key: value} read from Postgres, or None on failure."""
    if not init_schema():
        return None
    pool = _get_pool()
    if pool is None:
        return None
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT key, value FROM app_data")
            rows = cur.fetchall()
        return {r[0]: r[1] for r in rows} if rows else {}
    except Exception as e:
        log.error("PG load failed: %s", e)
        return None
    finally:
        _release(pool, conn)


def pg_save_all(data):
    """Transactionally replace the complete logical document in PostgreSQL.

    Upserts one JSONB row per top-level key in a single transaction and prunes
    rows whose key no longer exists in the submitted document. Returns True on
    commit and False on any failure; the caller must fail the mutation closed.
    """
    global _last_save_ok
    if not enabled():
        _last_save_ok = False
        return False
    if not isinstance(data, dict) or not data:
        _last_save_ok = False
        return False
    if not init_schema():
        _last_save_ok = False
        return False
    pool = _get_pool()
    if pool is None:
        _last_save_ok = False
        return False
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT key FROM app_data")
            existing = {r[0] for r in cur.fetchall()}
            rows = [(k, _pg_extras.Json(v)) for k, v in data.items() if isinstance(k, str)]
            if rows:
                cur.executemany(
                    "INSERT INTO app_data (key, value, updated_at) VALUES (%s, %s, now())"
                    " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                    rows,
                )
            stale = existing - set(data.keys())
            for k in stale:
                cur.execute("DELETE FROM app_data WHERE key = %s", (k,))
        conn.commit()
        _last_save_ok = True
        return True
    except Exception as e:
        try:
            if conn is not None:
                conn.rollback()
        except Exception:
            pass
        log.error("PG save failed: %s", e)
        _last_save_ok = False
        return False
    finally:
        _release(pool, conn)


def pg_seed_if_empty(data):
    """Atomically import a complete legacy document only into an empty DB.

    This is deliberately separate from pg_save_all: two app instances starting
    together cannot overwrite a database that another instance has already
    seeded. Every top-level key and JSON value is preserved losslessly.
    """
    global _last_save_ok
    if not isinstance(data, dict) or not data or not init_schema():
        return False
    pool = _get_pool()
    if pool is None:
        return False
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(7140622026)")
            cur.execute("SELECT COUNT(*) FROM app_data")
            if int(cur.fetchone()[0]) != 0:
                conn.rollback()
                return False
            rows = [(key, _pg_extras.Json(value)) for key, value in data.items()
                    if isinstance(key, str)]
            cur.executemany(
                "INSERT INTO app_data (key, value, updated_at) VALUES (%s, %s, now())",
                rows,
            )
            cur.execute("SELECT COUNT(*) FROM app_data")
            if int(cur.fetchone()[0]) != len(rows):
                raise RuntimeError('seed row count mismatch')
        conn.commit()
        _last_save_ok = True
        return True
    except Exception as exc:
        try:
            if conn is not None:
                conn.rollback()
        except Exception:
            pass
        log.error('PG seed failed for %s: %s', _safe_dsn(), exc)
        _last_save_ok = False
        return False
    finally:
        _release(pool, conn)


def last_save_ok():
    """True if the most recent authoritative write succeeded.

    None means no write attempt has happened yet this process (e.g. fresh
    start after a seed) - callers may treat None as 'trust Postgres'.
    """
    return _last_save_ok


def close_pool():
    global _pool
    with _pool_lock:
        if _pool is not None:
            try:
                _pool.closeall()
            except Exception:
                pass
            _pool = None
