"""SQLite-backed scan history. Each thread opens its own connection."""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, domain TEXT NOT NULL, status TEXT NOT NULL,
                    created REAL NOT NULL, started REAL, finished REAL,
                    options TEXT NOT NULL, error TEXT, count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS results (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    host TEXT NOT NULL, sources TEXT NOT NULL,
                    PRIMARY KEY (scan_id, host)
                );
            ''')
            db.execute("UPDATE scans SET status='interrupted', finished=?, error=? WHERE status IN ('queued', 'running')",
                       (time.time(), 'The application restarted before this scan finished. Run it again.'))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def decode(row):
        if row is None:
            return None
        scan = dict(row)
        scan['options'] = json.loads(scan['options'])
        # Existing scans belong to the first suite tool. No data migration is
        # needed to identify them in the shared activity interface.
        scan['tool'] = 'subdomains'
        return scan

    def get(self, scan_id):
        with self.connect() as db:
            return self.decode(db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone())

    def history(self):
        with self.connect() as db:
            return [self.decode(r) for r in db.execute('SELECT * FROM scans ORDER BY created DESC')]

    def create(self, scan_id, domain, options):
        with self.connect() as db:
            db.execute('INSERT INTO scans (id,domain,status,created,options) VALUES (?,?,?,?,?)',
                       (scan_id, domain, 'queued', time.time(), json.dumps(options)))
            db.execute("DELETE FROM scans WHERE id IN (SELECT id FROM scans WHERE status NOT IN ('queued','running') ORDER BY created DESC LIMIT -1 OFFSET 100)")

    def update(self, scan_id, **values):
        allowed = {'status', 'started', 'finished', 'error'}
        assert set(values) <= allowed
        with self.connect() as db:
            db.execute(f"UPDATE scans SET {','.join(k + '=?' for k in values)} WHERE id=?", (*values.values(), scan_id))
            if values.get('status') not in (None, 'queued', 'running'):
                db.execute("DELETE FROM scans WHERE id IN (SELECT id FROM scans WHERE status NOT IN ('queued','running') ORDER BY created DESC LIMIT -1 OFFSET 100)")

    def add_result(self, scan_id, host, sources):
        with self.connect() as db:
            row = db.execute('SELECT sources FROM results WHERE scan_id=? AND host=?', (scan_id, host)).fetchone()
            if row:
                sources = sorted(set(json.loads(row['sources'])) | set(sources))
                db.execute('UPDATE results SET sources=? WHERE scan_id=? AND host=?', (json.dumps(sources), scan_id, host))
            else:
                db.execute('INSERT INTO results VALUES (?,?,?)', (scan_id, host, json.dumps(sources)))
                db.execute('UPDATE scans SET count=count+1 WHERE id=?', (scan_id,))

    def results(self, scan_id, query='', offset=0, limit=200):
        query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        with self.connect() as db:
            params = (scan_id, '%' + query + '%')
            where = "scan_id=? AND host LIKE ? ESCAPE '\\'"
            total = db.execute('SELECT count(*) FROM results WHERE ' + where, params).fetchone()[0]
            rows = db.execute('SELECT host,sources FROM results WHERE ' + where + ' ORDER BY host LIMIT ? OFFSET ?',
                              (*params, limit, offset))
            return {'total': total, 'items': [{'host': r['host'], 'sources': json.loads(r['sources'])} for r in rows]}

    def delete(self, scan_id):
        with self.connect() as db:
            db.execute('DELETE FROM scans WHERE id=?', (scan_id,))
