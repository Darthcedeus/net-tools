"""Bounded, cancellable background Subfinder jobs; never invokes a shell."""
import json
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait

from app.resolver import resolve_host
from app.security import normalize_domain


class Runner:
    def __init__(self, store, binary='subfinder', provider_config=None, max_results=10_000, resolver=None):
        self.store = store
        self.binary = binary
        self.provider_config = provider_config
        self.max_results = max_results
        self.resolver = resolver or resolve_host
        self.jobs = queue.Queue(maxsize=5)
        self.lock = threading.RLock()
        self.cancellations = {}
        self.process = None
        self.stopping = threading.Event()
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.worker.start()

    def available(self):
        return shutil.which(self.binary) is not None

    def submit(self, domain, options):
        with self.lock:
            if self.stopping.is_set():
                raise ValueError('The application is shutting down.')
            if self.jobs.full():
                raise ValueError('The scan queue is full. Wait for a scan to finish.')
            scan_id = uuid.uuid4().hex
            self.store.create(scan_id, domain, options)
            self.cancellations[scan_id] = threading.Event()
            self.jobs.put_nowait(scan_id)
            return self.store.get(scan_id)

    def cancel(self, scan_id):
        with self.lock:
            event = self.cancellations.get(scan_id)
            if event:
                event.set()
                scan = self.store.get(scan_id)
                if scan and scan['status'] == 'queued':
                    self.store.update(scan_id, status='cancelled', finished=time.time())
            return event is not None

    def work(self):
        while not self.stopping.is_set():
            try:
                scan_id = self.jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.run(scan_id)
            except Exception:
                self.store.update(scan_id, status='failed', finished=time.time(), error='The scan could not be processed. Check server logs.')
                import logging
                logging.exception('Scan worker failed')
            finally:
                with self.lock:
                    self.cancellations.pop(scan_id, None)
                    self.process = None
                self.jobs.task_done()

    def run(self, scan_id):
        scan = self.store.get(scan_id)
        event = self.cancellations[scan_id]
        if event.is_set():
            self.store.update(scan_id, status='cancelled', finished=time.time())
            return
        opts = scan['options']
        # -cs JSON is emitted at the end. Verbose source records supply live
        # progress; the final JSON merges the complete attribution for each host.
        command = [self.binary, '-d', scan['domain'], '-json', '-cs', '-v', '-nc', '-duc',
                   '-timeout', str(opts['timeout']), '-max-time', str(opts['max_time']), '-rl', str(opts['rate_limit'])]
        if opts['all_sources']:
            command.append('-all')
        if opts['recursive']:
            command.append('-recursive')
        if self.provider_config:
            command.extend(['-pc', self.provider_config])
        self.store.update(scan_id, status='running', started=time.time())
        lines = queue.Queue(maxsize=256)
        reached_limit = threading.Event()
        deadline = time.monotonic() + opts['max_time'] * 60 + 30
        pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix='dns')
        lookups = set()
        status, error = 'failed', 'The scan could not be processed. Check server logs.'

        def lookup(host):
            if event.is_set() or self.stopping.is_set() or time.monotonic() >= deadline:
                return
            try:
                ips, dns_status = self.resolver(host)
            except Exception:
                ips, dns_status = [], 'error'
            self.store.set_addresses(scan_id, host, ips, dns_status)

        def schedule(host):
            lookups.add(pool.submit(lookup, host))

        try:
            status, error = self._consume(scan_id, scan, event, command, lines, reached_limit, deadline, schedule)
            pending = lookups
            while pending and not event.is_set() and not self.stopping.is_set() and time.monotonic() < deadline:
                _, pending = wait(pending, timeout=0.1)
            if event.is_set() or self.stopping.is_set():
                status = 'cancelled'
            elif pending and status == 'completed':
                status, error = 'timed_out', 'IP lookups reached the scan time limit. Partial results are saved.'
        finally:
            with self.lock:
                if self.process and self.process.poll() is None:
                    self.process.kill()
                    self.process.wait(timeout=3)
                self.process = None
            # Running DNS requests take at most three seconds; queued requests
            # are discarded on cancellation or deadline. Never leave workers
            # updating a finished/deleted scan.
            pool.shutdown(wait=True, cancel_futures=True)
            self.store.finish_addresses(scan_id, 'cancelled' if event.is_set() or self.stopping.is_set() else 'timeout' if time.monotonic() >= deadline else 'not_checked')
        self.store.update(scan_id, status=status, finished=time.time(), error=error)

    def _consume(self, scan_id, scan, event, command, lines, reached_limit, deadline, schedule):
        opts = scan['options']
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        except OSError:
            return 'failed', 'Subfinder is unavailable. Check the container build and binary path.'
        with self.lock:
            self.process = process

        def read_output(stream, mode):
            try:
                while True:
                    line = stream.readline(65537)
                    if not line:
                        break
                    if len(line) > 65536:
                        # Drain oversized records without retaining their contents.
                        while line and not line.endswith(b'\n'):
                            line = stream.readline(65537)
                        continue
                    while not self.stopping.is_set() and not event.is_set() and not reached_limit.is_set():
                        try:
                            lines.put((mode, line), timeout=0.2)
                            break
                        except queue.Full:
                            continue
            finally:
                stream.close()

        readers = [threading.Thread(target=read_output, args=(process.stdout, 'json'), daemon=True),
                   threading.Thread(target=read_output, args=(process.stderr, 'verbose'), daemon=True)]
        for reader in readers:
            reader.start()
        status, error = 'completed', None
        while any(reader.is_alive() for reader in readers) or not lines.empty() or process.poll() is None:
            if event.is_set() or self.stopping.is_set():
                status = 'cancelled'
                break
            if time.monotonic() >= deadline:
                status, error = 'timed_out', 'The scan reached its time limit. Partial results are saved.'
                break
            if self.store.get(scan_id)['count'] >= self.max_results:
                status, error = 'limited', f'The {self.max_results:,} result limit was reached. Partial results are saved.'
                reached_limit.set()
                break
            try:
                mode, line = lines.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if mode == 'verbose':
                    match = re.fullmatch(rb'\[([a-zA-Z0-9_-]{1,80})\]\s+([^\s]+)\s*', line)
                    if not match:
                        continue
                    item = {'host': match[2].decode(), 'source': match[1].decode()}
                else:
                    item = json.loads(line)
                host = normalize_domain(item['host'])
                if host != scan['domain'] and not host.endswith('.' + scan['domain']):
                    continue
                sources = item.get('sources') or [item.get('source', 'unknown')]
                if not isinstance(sources, list):
                    sources = [sources]
                sources = sorted({s[:80] for s in sources if isinstance(s, str)})[:100]
                if self.store.add_result(scan_id, host, sources):
                    schedule(host)
            except (ValueError, KeyError, TypeError, UnicodeError):
                continue
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait()
        for reader in readers:
            reader.join(timeout=3)
        if status == 'completed' and process.returncode != 0:
            # Provider logs can include secrets; never send raw stderr to the browser.
            status, error = 'failed', 'Subfinder exited with an error. Check the provider configuration. Partial results are saved.'
        return status, error

    def close(self):
        self.stopping.set()
        with self.lock:
            for event in self.cancellations.values():
                event.set()
        self.worker.join(timeout=10)
