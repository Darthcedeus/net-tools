"""Bounded, cancellable background HTTP/HTTPS reachability batches.

Mirrors the Salesforce runner's queue/cancel/resume shape, but a batch is a
single durable job: one ``reach_batches`` row with many pending host rows. A
worker claims a queued batch, probes its hosts with bounded concurrency through
the injectable prober, records each result, and marks the batch finished. Only
one batch runs at a time; pending hosts survive a restart and resume.
"""
import logging
import queue
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.reachability import probe_host

MAX_BATCH_SECONDS = 1200


class ReachabilityRunner:
    def __init__(self, store, prober=None, max_batch_seconds=MAX_BATCH_SECONDS):
        self.store = store
        self.prober = prober or probe_host
        self.max_batch_seconds = max_batch_seconds
        self.jobs = queue.Queue(maxsize=5)
        self.lock = threading.RLock()
        self.queued = set()
        self.stopping = threading.Event()
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.worker.start()

    def available(self):
        # The prober uses only the Python standard library.
        return True

    def submit_batch(self, source_id, options, hosts=None, query=''):
        with self.lock:
            if self.stopping.is_set():
                raise ValueError('The application is shutting down.')
            return self.store.reach_batch_create(uuid.uuid4().hex, source_id, options, hosts, query)

    def cancel_batch(self, batch_id):
        with self.lock:
            batch = self.store.reach_batch_get(batch_id, items=False)
            if not batch or batch['status'] not in ('queued', 'running'):
                return
            self.store.reach_batch_cancel(batch_id)

    def fill_queue(self):
        # Queued batches live in SQLite, so capacity never loses a batch and a
        # queued batch resumes after restart.
        with self.lock:
            for batch_id in self.store.reach_pending():
                if self.jobs.full() or self.stopping.is_set():
                    break
                if batch_id not in self.queued:
                    self.queued.add(batch_id)
                    self.jobs.put_nowait(batch_id)

    def work(self):
        while not self.stopping.is_set():
            self.fill_queue()
            try:
                batch_id = self.jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.run(batch_id)
            except Exception:
                logging.exception('Reachability batch worker failed')
                self.store.reach_finish(batch_id, error='The batch could not be processed. Check server logs.')
            finally:
                with self.lock:
                    self.queued.discard(batch_id)
                self.jobs.task_done()

    def run(self, batch_id):
        hosts = self.store.reach_start(batch_id)
        if not hosts:
            # Already cancelled, missing, or no pending hosts: settle the state.
            if self.store.reach_batch_get(batch_id, items=False):
                self.store.reach_finish(batch_id)
            return
        batch = self.store.reach_batch_get(batch_id, items=False)
        options = batch['options'] if batch else {}
        timeout = options.get('timeout', 8)
        concurrency = max(1, min(options.get('concurrency', 10), 20))
        deadline = time.monotonic() + self.max_batch_seconds
        timed_out = False

        def cancelled():
            return self.stopping.is_set() or self.store.reach_cancelled(batch_id)

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            pending = iter(hosts)
            futures = {}
            # Prime the pool, then keep it topped up as results arrive so a large
            # batch never builds an unbounded backlog of in-flight probes.
            for _ in range(concurrency):
                host = next(pending, None)
                if host is None:
                    break
                futures[pool.submit(self.prober, host, timeout)] = host
            while futures:
                for future in as_completed(list(futures)):
                    host = futures.pop(future)
                    try:
                        self.store.reach_record(batch_id, future.result())
                    except Exception:
                        logging.exception('Reachability probe failed for a host')
                        self.store.reach_record(batch_id, self._error_result(host))
                    if time.monotonic() >= deadline:
                        timed_out = True
                    if cancelled() or timed_out:
                        futures.clear()
                        break
                    nxt = next(pending, None)
                    if nxt is not None:
                        futures[pool.submit(self.prober, nxt, timeout)] = nxt
                    break
        self.store.reach_finish(batch_id, error=None, timed_out=timed_out)

    @staticmethod
    def _error_result(host):
        return {'host': host, 'reachable': False, 'scheme': None, 'status': None,
                'server': None, 'final_url': None, 'error': 'probe_error',
                'elapsed_ms': None, 'details': {}}

    def close(self):
        self.stopping.set()
        self.worker.join(timeout=10)
