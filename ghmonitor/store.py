"""SQLite 存储与指纹去重。"""
import hashlib
import sqlite3
from datetime import datetime, timezone

from .scanner import mask_key

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL,          -- sha256(完整密钥) 前 16 位
  key_type TEXT NOT NULL,
  key_masked TEXT NOT NULL,
  key_full TEXT NOT NULL,             -- 完整密钥仅保存在本地库，供事件响应使用
  repo TEXT NOT NULL,
  path TEXT NOT NULL,
  line INTEGER NOT NULL,
  url TEXT DEFAULT '',
  source TEXT DEFAULT 'github',       -- github / local
  verified TEXT DEFAULT '',           -- '' 未校验 / valid / invalid / ...
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  seen_count INTEGER DEFAULT 1,
  UNIQUE(fingerprint, repo, path, line)
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def save(self, *, key: str, key_type: str, repo: str, path: str,
             line: int, url: str, source: str = "github") -> str:
        """写入发现；返回 'new'（首次）或 'seen'（重复命中，更新计数）。"""
        fp = fingerprint(key)
        row = self.conn.execute(
            "SELECT id FROM findings WHERE fingerprint=? AND repo=? AND path=? AND line=?",
            (fp, repo, path, line)).fetchone()
        if row:
            self.conn.execute(
                "UPDATE findings SET last_seen=?, seen_count=seen_count+1 "
                "WHERE fingerprint=? AND repo=? AND path=? AND line=?",
                (now_iso(), fp, repo, path, line))
            self.conn.commit()
            return "seen"
        self.conn.execute(
            "INSERT INTO findings(fingerprint,key_type,key_masked,key_full,"
            "repo,path,line,url,source,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (fp, key_type, mask_key(key), key, repo, path, line, url, source,
             now_iso(), now_iso()))
        self.conn.commit()
        return "new"

    def mark_verified(self, fp: str, status: str):
        self.conn.execute("UPDATE findings SET verified=? WHERE fingerprint=?",
                          (status, fp))
        self.conn.commit()

    def unverified_fingerprints(self) -> list:
        rows = self.conn.execute(
            "SELECT DISTINCT fingerprint, key_full, key_type FROM findings "
            "WHERE verified='' ORDER BY first_seen").fetchall()
        return [(r["fingerprint"], r["key_full"], r["key_type"]) for r in rows]

    def all(self) -> list:
        return self.conn.execute(
            "SELECT * FROM findings ORDER BY first_seen DESC").fetchall()

    def stats(self) -> sqlite3.Row:
        return self.conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT fingerprint) AS keys, "
            "COUNT(DISTINCT repo) AS repos FROM findings").fetchone()

    def close(self):
        self.conn.close()
