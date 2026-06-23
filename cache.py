import sqlite3
import json
import time
import config 

DB_PATCH = "cache.db"

def get_Connection():
    return sqlite3.connect(DB_PATCH)

def init_cache():
    with get_Connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip          TEXT PRIMARY KEY,
                vt_result   TEXT NOT NULL,
                abuse_result TEXT NOT NULL,
                fetched_at  REAL NOT NULL
            )
        """)
        conn.commit()

def get_cached(ip):
    # this will return vt result and abuse result
    with get_Connection() as conn:
        row = conn.execute("SELECT vt_result, abuse_result, fetched_at FROM ip_cache WHERE ip = ?",
            (ip,)
        ).fetchone()

    if row is None:
        return None
    
    vt_result, abuse_result, fetched_at = row
    age_hours = (time.time() - fetched_at) / 3600

    if age_hours > config.CACHE_TTL_HOURS:
        return None
    
    return json.loads(vt_result), json.loads(abuse_result)

def save_to_cache(ip, vt_result, abuse_result):
    
    if vt_result.get("status") != "ok" or abuse_result.get("status") != "ok":
        return  # do not cache failures — next run should retry the real API

    with get_Connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO ip_cache (ip, vt_result, abuse_result, fetched_at)
            VALUES (?, ?, ?, ?)
        """, (
            ip,
            json.dumps(vt_result),
            json.dumps(abuse_result),
            time.time()
        ))
        conn.commit()

