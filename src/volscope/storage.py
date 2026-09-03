"""Case-local SQLite persistence. No global or cross-image cache reuse."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def identity(path):
    path = Path(path).resolve()
    stat = path.stat()
    return {"path": str(path), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


class Case:
    def __init__(self, path):
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS results (key TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, time TEXT, plugin TEXT,
                status TEXT, command TEXT, diagnostics TEXT);
        ''')

    def set_image(self, path):
        self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('image', ?)", (json.dumps(identity(path)),))
        self.db.commit()

    def image(self):
        row = self.db.execute("SELECT value FROM metadata WHERE key='image'").fetchone()
        return json.loads(row[0]) if row else None

    def save(self, key, rows):
        self.db.execute("INSERT OR REPLACE INTO results VALUES (?, ?)", (key, json.dumps(rows)))
        self.db.commit()

    def load(self):
        return {key: json.loads(data) for key, data in self.db.execute("SELECT key,data FROM results")}

    def record(self, key, status, args, diagnostics):
        self.db.execute("INSERT INTO runs(time,plugin,status,command,diagnostics) VALUES (?,?,?,?,?)",
                        (datetime.now(timezone.utc).isoformat(), key, status, json.dumps(args), diagnostics))
        self.db.commit()

    def close(self):
        self.db.close()
