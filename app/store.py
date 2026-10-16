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
                CREATE TABLE IF NOT EXISTS sf_scans (
                    id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT NOT NULL,
                    created REAL NOT NULL, started REAL, finished REAL,
                    options TEXT NOT NULL, error TEXT,
                    verdict TEXT, is_salesforce INTEGER NOT NULL DEFAULT 0,
                    aura_endpoint TEXT, details TEXT NOT NULL DEFAULT '{}',
                    count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS sf_findings (
                    scan_id TEXT NOT NULL REFERENCES sf_scans(id) ON DELETE CASCADE,
                    object TEXT NOT NULL, key_prefix TEXT,
                    readable INTEGER NOT NULL DEFAULT 0, record_count INTEGER,
                    samples TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (scan_id, object)
                );
            ''')
            columns = {r['name'] for r in db.execute('PRAGMA table_info(results)')}
            if 'ips' not in columns:
                db.execute("ALTER TABLE results ADD COLUMN ips TEXT NOT NULL DEFAULT '[]'")
            if 'dns_status' not in columns:
                db.execute("ALTER TABLE results ADD COLUMN dns_status TEXT NOT NULL DEFAULT 'not_checked'")
            db.execute("UPDATE results SET dns_status='not_checked' WHERE dns_status='pending'")
            interrupted = 'The application restarted before this scan finished. Run it again.'
            db.execute("UPDATE scans SET status='interrupted', finished=?, error=? WHERE status IN ('queued', 'running')",
                       (time.time(), interrupted))
            db.execute("UPDATE sf_scans SET status='interrupted', finished=?, error=? WHERE status IN ('queued', 'running')",
                       (time.time(), interrupted))

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
                db.execute("INSERT INTO results (scan_id,host,sources,dns_status) VALUES (?,?,?,'pending')", (scan_id, host, json.dumps(sources)))
                db.execute('UPDATE scans SET count=count+1 WHERE id=?', (scan_id,))
            return row is None

    def set_addresses(self, scan_id, host, ips, status):
        with self.connect() as db:
            db.execute('UPDATE results SET ips=?,dns_status=? WHERE scan_id=? AND host=?',
                       (json.dumps(ips), status, scan_id, host))

    def finish_addresses(self, scan_id, status):
        with self.connect() as db:
            db.execute("UPDATE results SET dns_status=? WHERE scan_id=? AND dns_status='pending'", (status, scan_id))

    def results(self, scan_id, query='', offset=0, limit=200):
        query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        with self.connect() as db:
            params = (scan_id, '%' + query + '%')
            where = "scan_id=? AND host LIKE ? ESCAPE '\\'"
            total = db.execute('SELECT count(*) FROM results WHERE ' + where, params).fetchone()[0]
            rows = db.execute('SELECT host,sources,ips,dns_status FROM results WHERE ' + where + ' ORDER BY host LIMIT ? OFFSET ?',
                              (*params, limit, offset))
            return {'total': total, 'items': [{'host': r['host'], 'sources': json.loads(r['sources']),
                                             'ips': json.loads(r['ips']), 'dns_status': r['dns_status']} for r in rows]}

    def delete(self, scan_id):
        with self.connect() as db:
            db.execute('DELETE FROM scans WHERE id=?', (scan_id,))

    # -- Salesforce detector -------------------------------------------------

    @staticmethod
    def decode_sf(row):
        if row is None:
            return None
        scan = dict(row)
        scan['options'] = json.loads(scan['options'])
        scan['details'] = json.loads(scan['details'])
        scan['is_salesforce'] = bool(scan['is_salesforce'])
        scan['tool'] = 'salesforce'
        return scan

    def sf_get(self, scan_id):
        with self.connect() as db:
            return self.decode_sf(db.execute('SELECT * FROM sf_scans WHERE id=?', (scan_id,)).fetchone())

    def sf_history(self):
        with self.connect() as db:
            return [self.decode_sf(r) for r in db.execute('SELECT * FROM sf_scans ORDER BY created DESC')]

    def sf_create(self, scan_id, url, options):
        with self.connect() as db:
            db.execute('INSERT INTO sf_scans (id,url,status,created,options) VALUES (?,?,?,?,?)',
                       (scan_id, url, 'queued', time.time(), json.dumps(options)))
            db.execute("DELETE FROM sf_scans WHERE id IN (SELECT id FROM sf_scans WHERE status NOT IN ('queued','running') ORDER BY created DESC LIMIT -1 OFFSET 100)")

    def sf_update(self, scan_id, **values):
        allowed = {'status', 'started', 'finished', 'error'}
        assert set(values) <= allowed
        with self.connect() as db:
            db.execute(f"UPDATE sf_scans SET {','.join(k + '=?' for k in values)} WHERE id=?", (*values.values(), scan_id))
            if values.get('status') not in (None, 'queued', 'running'):
                db.execute("DELETE FROM sf_scans WHERE id IN (SELECT id FROM sf_scans WHERE status NOT IN ('queued','running') ORDER BY created DESC LIMIT -1 OFFSET 100)")

    def sf_set_summary(self, scan_id, summary):
        with self.connect() as db:
            db.execute('UPDATE sf_scans SET verdict=?,is_salesforce=?,aura_endpoint=?,details=? WHERE id=?',
                       (summary.get('verdict'), 1 if summary.get('is_salesforce') else 0,
                        summary.get('aura_endpoint'), json.dumps(summary), scan_id))

    def sf_add_finding(self, scan_id, finding):
        with self.connect() as db:
            existing = db.execute('SELECT object FROM sf_findings WHERE scan_id=? AND object=?',
                                  (scan_id, finding['object'])).fetchone()
            db.execute('INSERT OR REPLACE INTO sf_findings (scan_id,object,key_prefix,readable,record_count,samples) '
                       'VALUES (?,?,?,?,?,?)',
                       (scan_id, finding['object'], finding.get('key_prefix'),
                        1 if finding.get('readable') else 0, finding.get('record_count'),
                        json.dumps(finding.get('samples', []))))
            if finding.get('readable'):
                db.execute('UPDATE sf_scans SET count=(SELECT count(*) FROM sf_findings WHERE scan_id=? AND readable=1) WHERE id=?',
                           (scan_id, scan_id))
            return existing is None

    def sf_findings(self, scan_id, query='', readable_only=False, offset=0, limit=200):
        query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        with self.connect() as db:
            where = "scan_id=? AND object LIKE ? ESCAPE '\\'" + (' AND readable=1' if readable_only else '')
            params = (scan_id, '%' + query + '%')
            total = db.execute('SELECT count(*) FROM sf_findings WHERE ' + where, params).fetchone()[0]
            rows = db.execute('SELECT object,key_prefix,readable,record_count,samples FROM sf_findings WHERE '
                              + where + ' ORDER BY readable DESC, object LIMIT ? OFFSET ?',
                              (*params, limit, offset))
            return {'total': total, 'items': [{'object': r['object'], 'key_prefix': r['key_prefix'],
                                               'readable': bool(r['readable']), 'record_count': r['record_count'],
                                               'samples': json.loads(r['samples'])} for r in rows]}

    def sf_delete(self, scan_id):
        with self.connect() as db:
            db.execute('DELETE FROM sf_scans WHERE id=?', (scan_id,))

    # -- shared activity across tools ---------------------------------------

    def activity(self):
        """Merge both tools' scans into a common shape for the shared feed."""
        items = []
        with self.connect() as db:
            for r in db.execute('SELECT id,domain,status,created,started,finished,count FROM scans'):
                items.append({'id': r['id'], 'tool': 'subdomains', 'label': r['domain'],
                              'status': r['status'], 'created': r['created'], 'started': r['started'],
                              'finished': r['finished'], 'count': r['count'], 'verdict': None})
            for r in db.execute('SELECT id,url,status,created,started,finished,count,verdict,is_salesforce FROM sf_scans'):
                items.append({'id': r['id'], 'tool': 'salesforce', 'label': r['url'],
                              'status': r['status'], 'created': r['created'], 'started': r['started'],
                              'finished': r['finished'], 'count': r['count'],
                              'verdict': r['verdict'] if r['is_salesforce'] else 'not_salesforce'})
        items.sort(key=lambda item: item['created'], reverse=True)
        return items
