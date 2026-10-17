"""SQLite-backed scan history. Each thread opens its own connection."""
import json
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

MAX_SF_BATCH_HOSTS = 100


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
                CREATE TABLE IF NOT EXISTS sf_batches (
                    id TEXT PRIMARY KEY,
                    source_scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    source_domain TEXT NOT NULL, created REAL NOT NULL,
                    options TEXT NOT NULL, query TEXT NOT NULL DEFAULT '',
                    cancelled INTEGER NOT NULL DEFAULT 0
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
            sf_columns = {r['name'] for r in db.execute('PRAGMA table_info(sf_scans)')}
            if 'batch_id' not in sf_columns:
                db.execute('ALTER TABLE sf_scans ADD COLUMN batch_id TEXT REFERENCES sf_batches(id) ON DELETE CASCADE')
            db.execute('CREATE INDEX IF NOT EXISTS sf_batch_scans ON sf_scans(batch_id, status)')
            db.execute("UPDATE results SET dns_status='not_checked' WHERE dns_status='pending'")
            interrupted = 'The application restarted before this scan finished. Run it again.'
            db.execute("UPDATE scans SET status='interrupted', finished=?, error=? WHERE status IN ('queued', 'running')",
                       (time.time(), interrupted))
            # Pending batch hosts resume after restart; a host that was already
            # running is marked interrupted rather than silently scanned twice.
            db.execute("UPDATE sf_scans SET status='interrupted', finished=?, error=? WHERE status='running' OR (status='queued' AND batch_id IS NULL)",
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
            self._trim_subdomains(db)

    def update(self, scan_id, **values):
        allowed = {'status', 'started', 'finished', 'error'}
        assert set(values) <= allowed
        with self.connect() as db:
            db.execute(f"UPDATE scans SET {','.join(k + '=?' for k in values)} WHERE id=?", (*values.values(), scan_id))
            if values.get('status') not in (None, 'queued', 'running'):
                self._trim_subdomains(db)

    @staticmethod
    def _trim_subdomains(db):
        db.execute("DELETE FROM scans WHERE id IN (SELECT id FROM scans WHERE status NOT IN ('queued','running') AND id NOT IN (SELECT source_scan_id FROM sf_batches) ORDER BY created DESC LIMIT -1 OFFSET 100)")

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
            self._trim_salesforce(db)

    def sf_update(self, scan_id, **values):
        allowed = {'status', 'started', 'finished', 'error'}
        assert set(values) <= allowed
        with self.connect() as db:
            db.execute(f"UPDATE sf_scans SET {','.join(k + '=?' for k in values)} WHERE id=?", (*values.values(), scan_id))
            if values.get('status') not in (None, 'queued', 'running'):
                self._trim_salesforce(db)

    @staticmethod
    def _trim_salesforce(db):
        db.execute("DELETE FROM sf_batches WHERE id IN (SELECT b.id FROM sf_batches b WHERE NOT EXISTS (SELECT 1 FROM sf_scans s WHERE s.batch_id=b.id AND s.status IN ('queued','running')) ORDER BY b.created DESC LIMIT -1 OFFSET 10)")
        db.execute("DELETE FROM sf_scans WHERE id IN (SELECT id FROM sf_scans WHERE batch_id IS NULL AND status NOT IN ('queued','running') ORDER BY created DESC LIMIT -1 OFFSET 100)")

    def sf_pending(self, limit=12):
        with self.connect() as db:
            return [r['id'] for r in db.execute("SELECT id FROM sf_scans WHERE status='queued' ORDER BY created,id LIMIT ?", (limit,))]

    def sf_batch_create(self, batch_id, source_id, options, hosts=None, query=''):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            source = db.execute('SELECT domain,status FROM scans WHERE id=?', (source_id,)).fetchone()
            if source is None:
                raise ValueError('The source discovery scan no longer exists.')
            if source['status'] in ('queued', 'running'):
                raise ValueError('Wait for subdomain discovery to finish before starting a Salesforce batch.')
            if db.execute("SELECT 1 FROM sf_scans WHERE batch_id IS NOT NULL AND status IN ('queued','running') LIMIT 1").fetchone():
                raise ValueError('A Salesforce batch is already active. Wait for it to finish or cancel it.')
            if hosts is None:
                escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
                hosts = [r['host'] for r in db.execute("SELECT host FROM results WHERE scan_id=? AND host LIKE ? ESCAPE '\\' ORDER BY host LIMIT ?",
                                                      (source_id, '%' + escaped + '%', MAX_SF_BATCH_HOSTS + 1))]
            else:
                hosts = sorted(set(hosts))
                found = {r['host'] for r in db.execute('SELECT host FROM results WHERE scan_id=? AND host IN (' + ','.join('?' for _ in hosts) + ')', (source_id, *hosts))}
                if found != set(hosts):
                    raise ValueError('Select only hosts saved in this discovery scan.')
            if not hosts:
                raise ValueError('No subdomains match this selection.')
            if len(hosts) > MAX_SF_BATCH_HOSTS:
                raise ValueError(f'Choose up to {MAX_SF_BATCH_HOSTS} hosts or narrow the subdomain filter. No scans were queued.')
            if any(host != source['domain'] and not host.endswith('.' + source['domain']) for host in hosts):
                raise ValueError('A selected host is outside the discovery domain.')
            now = time.time()
            db.execute('INSERT INTO sf_batches (id,source_scan_id,source_domain,created,options,query) VALUES (?,?,?,?,?,?)',
                       (batch_id, source_id, source['domain'], now, json.dumps(options), query))
            db.executemany('INSERT INTO sf_scans (id,url,status,created,options,batch_id) VALUES (?,?,?,?,?,?)',
                           [(uuid.uuid4().hex, 'https://' + host, 'queued', now + i / 100000, json.dumps(options), batch_id) for i, host in enumerate(hosts)])
            self._trim_salesforce(db)
        return self.sf_batch_get(batch_id)

    def sf_batch_get(self, batch_id, items=True):
        with self.connect() as db:
            row = db.execute('SELECT * FROM sf_batches WHERE id=?', (batch_id,)).fetchone()
            if row is None:
                return None
            batch = dict(row)
            batch['options'] = json.loads(batch['options'])
            rows = [dict(r) for r in db.execute('SELECT id,url,status,started,finished,error,verdict,is_salesforce,aura_endpoint,count FROM sf_scans WHERE batch_id=? ORDER BY url', (batch_id,))]
        counts = {name: sum(r['status'] == name for r in rows) for name in ('queued', 'running', 'completed', 'failed', 'cancelled', 'timed_out', 'interrupted')}
        batch.update(counts)
        batch['total'] = len(rows)
        batch['done'] = len(rows) - counts['queued'] - counts['running']
        batch['salesforce'] = sum(bool(r['is_salesforce']) for r in rows)
        batch['leaking'] = sum(r['verdict'] == 'leaking' for r in rows)
        batch['started'] = min((r['started'] for r in rows if r['started'] is not None), default=None)
        batch['finished'] = max((r['finished'] for r in rows if r['finished'] is not None), default=None) if batch['done'] == batch['total'] else None
        batch['status'] = ('running' if batch['started'] is not None else 'queued') if batch['done'] < batch['total'] else ('cancelled' if row['cancelled'] else 'completed')
        batch['cancel_requested'] = bool(row['cancelled'])
        if items:
            batch['items'] = rows
        return batch

    def sf_batches(self, source_id=None):
        with self.connect() as db:
            ids = [r['id'] for r in db.execute('SELECT id FROM sf_batches' + (' WHERE source_scan_id=?' if source_id else '') + ' ORDER BY created DESC', (source_id,) if source_id else ())]
        return [batch for batch_id in ids if (batch := self.sf_batch_get(batch_id, items=False)) is not None]

    def sf_batch_cancel(self, batch_id):
        with self.connect() as db:
            db.execute('UPDATE sf_batches SET cancelled=1 WHERE id=?', (batch_id,))
            db.execute("UPDATE sf_scans SET status='cancelled',finished=? WHERE batch_id=? AND status='queued'", (time.time(), batch_id))
            self._trim_salesforce(db)

    def sf_batch_delete(self, batch_id):
        with self.connect() as db:
            db.execute('DELETE FROM sf_batches WHERE id=?', (batch_id,))
            self._trim_subdomains(db)

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

    def delete_activities(self, items):
        """Validate the whole selection before deleting anything, including cascades."""
        if not isinstance(items, list) or not 1 <= len(items) <= 500:
            raise ValueError('Select between 1 and 500 activities.')
        selection = set()
        for item in items:
            if (not isinstance(item, dict) or item.get('kind') not in ('subdomains', 'salesforce', 'salesforce_batch')
                    or not isinstance(item.get('id'), str) or not re.fullmatch(r'[a-f0-9]{32}', item['id'])):
                raise ValueError('Invalid activity selection.')
            key = (item['kind'], item['id'])
            if key in selection:
                raise ValueError('Select each activity only once.')
            selection.add(key)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for kind, activity_id in selection:
                if kind == 'salesforce_batch':
                    row = db.execute('SELECT id FROM sf_batches WHERE id=?', (activity_id,)).fetchone()
                    busy = db.execute("SELECT 1 FROM sf_scans WHERE batch_id=? AND status IN ('queued','running') LIMIT 1", (activity_id,)).fetchone()
                elif kind == 'salesforce':
                    row = db.execute('SELECT status,batch_id FROM sf_scans WHERE id=?', (activity_id,)).fetchone()
                    if row is not None and row['batch_id'] is not None:
                        raise ValueError('Select the Salesforce batch instead of an individual batch result.')
                    busy = row is not None and row['status'] in ('queued', 'running')
                else:
                    row = db.execute('SELECT status FROM scans WHERE id=?', (activity_id,)).fetchone()
                    busy = row is not None and row['status'] in ('queued', 'running')
                    busy = busy or db.execute("SELECT 1 FROM sf_scans s JOIN sf_batches b ON s.batch_id=b.id WHERE b.source_scan_id=? AND s.status IN ('queued','running') LIMIT 1", (activity_id,)).fetchone()
                if row is None:
                    raise ValueError('Activity history changed. Refresh and select the activities again. Nothing was deleted.')
                if busy:
                    raise ValueError('Cancel active scans and Salesforce batches and wait for them to stop. Nothing was deleted.')
            # Batch-first ordering also handles a selected discovery plus its
            # selected batch. Source deletion still cascades any other batches.
            for kind, table in (('salesforce_batch', 'sf_batches'), ('salesforce', 'sf_scans'), ('subdomains', 'scans')):
                db.executemany(f'DELETE FROM {table} WHERE id=?', [(activity_id,) for selected_kind, activity_id in selection if selected_kind == kind])
        return {'deleted': len(selection)}

    def activity(self):
        """Merge both tools' scans into a common shape for the shared feed."""
        items = []
        with self.connect() as db:
            for r in db.execute('SELECT id,domain,status,created,started,finished,count FROM scans'):
                items.append({'id': r['id'], 'tool': 'subdomains', 'label': r['domain'],
                              'status': r['status'], 'created': r['created'], 'started': r['started'],
                              'finished': r['finished'], 'count': r['count'], 'verdict': None})
            for r in db.execute('SELECT id,url,status,created,started,finished,count,verdict,is_salesforce FROM sf_scans WHERE batch_id IS NULL'):
                items.append({'id': r['id'], 'tool': 'salesforce', 'label': r['url'],
                              'status': r['status'], 'created': r['created'], 'started': r['started'],
                              'finished': r['finished'], 'count': r['count'],
                              'verdict': r['verdict']})
        for batch in self.sf_batches():
            items.append({'id': batch['id'], 'batch_id': batch['id'], 'source_scan_id': batch['source_scan_id'],
                          'tool': 'salesforce', 'label': batch['source_domain'], 'status': batch['status'],
                          'created': batch['created'], 'started': batch['started'], 'finished': batch['finished'],
                          'count': batch['done'], 'total': batch['total'], 'leaking': batch['leaking'], 'verdict': None})
        protected_sources = {item['source_scan_id'] for item in items if item.get('batch_id') and item['status'] in ('queued', 'running')}
        for item in items:
            item['delete_kind'] = 'salesforce_batch' if item.get('batch_id') else item['tool']
            item['deletable'] = item['status'] not in ('queued', 'running') and not (item['tool'] == 'subdomains' and item['id'] in protected_sources)
        items.sort(key=lambda item: item['created'], reverse=True)
        return items

