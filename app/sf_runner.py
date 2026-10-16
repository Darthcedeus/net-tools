"""Bounded, cancellable background Salesforce detector jobs.

Mirrors the Subfinder runner's queue/cancel/deadline shape, but the work is
pure-Python HTTP through the injectable Detector rather than a subprocess.
"""
import logging
import queue
import threading
import time
import uuid

from app.salesforce import Detector


class SalesforceRunner:
    def __init__(self, store, detector=None, max_scan_seconds=180):
        self.store = store
        self.detector = detector or Detector()
        self.max_scan_seconds = max_scan_seconds
        self.jobs = queue.Queue(maxsize=5)
        self.lock = threading.RLock()
        self.cancellations = {}
        self.stopping = threading.Event()
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.worker.start()

    def available(self):
        # The detector uses only the Python standard library.
        return True

    def submit(self, url, options):
        with self.lock:
            if self.stopping.is_set():
                raise ValueError('The application is shutting down.')
            if self.jobs.full():
                raise ValueError('The scan queue is full. Wait for a scan to finish.')
            scan_id = uuid.uuid4().hex
            self.store.sf_create(scan_id, url, options)
            self.cancellations[scan_id] = threading.Event()
            self.jobs.put_nowait(scan_id)
            return self.store.sf_get(scan_id)

    def cancel(self, scan_id):
        with self.lock:
            event = self.cancellations.get(scan_id)
            if event:
                event.set()
                scan = self.store.sf_get(scan_id)
                if scan and scan['status'] == 'queued':
                    self.store.sf_update(scan_id, status='cancelled', finished=time.time())
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
                self.store.sf_update(scan_id, status='failed', finished=time.time(),
                                     error='The scan could not be processed. Check server logs.')
                logging.exception('Salesforce scan worker failed')
            finally:
                with self.lock:
                    self.cancellations.pop(scan_id, None)
                self.jobs.task_done()

    def run(self, scan_id):
        scan = self.store.sf_get(scan_id)
        event = self.cancellations[scan_id]
        if event.is_set():
            self.store.sf_update(scan_id, status='cancelled', finished=time.time())
            return
        options = scan['options']
        deadline = time.monotonic() + min(options.get('max_time', 2) * 60, self.max_scan_seconds)
        self.store.sf_update(scan_id, status='running', started=time.time())

        def cancelled():
            return event.is_set() or self.stopping.is_set() or time.monotonic() >= deadline

        def emit(kind, payload):
            if kind == 'finding':
                self.store.sf_add_finding(scan_id, payload)
            elif kind == 'meta':
                self.store.sf_set_summary(scan_id, payload)

        detector = Detector(fetch=self.detector.fetch,
                            sample_size=options.get('sample_size', 10),
                            max_objects=options.get('max_objects', 50),
                            request_timeout=options.get('request_timeout', 10))
        status, error = 'completed', None
        try:
            detector.run(scan['url'], cancelled, emit)
        except ValueError as exception:
            status, error = 'failed', str(exception)
        except Exception:
            logging.exception('Salesforce detector failed')
            status, error = 'failed', 'The scan could not be processed. Check server logs.'
        if event.is_set() or self.stopping.is_set():
            status, error = 'cancelled', None
        elif status == 'completed' and time.monotonic() >= deadline:
            status, error = 'timed_out', 'The scan reached its time limit. Partial results are saved.'
        self.store.sf_update(scan_id, status=status, finished=time.time(), error=error)

    def close(self):
        self.stopping.set()
        with self.lock:
            for event in self.cancellations.values():
                event.set()
        self.worker.join(timeout=10)
