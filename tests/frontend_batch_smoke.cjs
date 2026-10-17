// DOM simulation for actual app.js event wiring; this is not visual/browser QA.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const root = require('path').resolve(__dirname, '..');
const html = fs.readFileSync(root + '/app/static/index.html', 'utf8');
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
assert.equal(ids.length, new Set(ids).size, 'duplicate HTML ids');
class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.listeners = {}; this.value = ''; this.hidden = false; this.disabled = false; this.dataset = {}; this.classList = { toggle() {}, add() {}, remove() {} }; this.attrs = {}; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text || '') + this.children.map(n => n.textContent || '').join(''); }
  append(...nodes) { for (const n of nodes) this.children.push(...(n.fragment ? n.children : [typeof n === 'string' ? { textContent: n } : n])); }
  replaceChildren(...nodes) { this.children = []; this.text = ''; this.append(...nodes); }
  setAttribute(k, v) { this.attrs[k] = v; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(name, cb) { (this.listeners[name] ||= []).push(cb); }
  async fire(name) { for (const cb of this.listeners[name] || []) await cb({ preventDefault() {}, target: this }); }
  querySelector(tag) { return this.children.find(n => n.tag === tag) || new Element(tag); }
  reportValidity() { return true; }
  focus() {} scrollIntoView() {} remove() {} click() {}
}
const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
elements['batch-sample-size'].value = '10'; elements['batch-max-objects'].value = '50';
const doc = { hidden: false, title: '', body: new Element(), getElementById(id) { assert(elements[id], `Missing HTML control: ${id}`); return elements[id]; },
  createElement: tag => new Element(tag), createTextNode: textContent => ({ textContent }), createDocumentFragment() { const e = new Element(); e.fragment = true; return e; }, addEventListener() {} };
const sourceId = 'f'.repeat(32), location = { pathname: '/tools/subdomains', search: '?scan=' + sourceId };
const source = { id: sourceId, domain: 'example.com', status: 'completed', count: 201, options: {}, created: 1, started: 1, finished: 2 };
const hosts = [{ host: 'api.example.com', sources: ['fixture'], ips: [], dns_status: 'no_records' }, { host: 'support.example.com', sources: ['fixture'], ips: [], dns_status: 'no_records' }];
const batches = [], sent = [];
const summary = b => { const { items, ...rest } = b; return rest; };
async function fetch(path, options = {}) {
  let value;
  if (path === '/api/session') value = { authenticated: true, csrf: 'test', engine_available: true };
  else if (path === '/api/activity') value = [];
  else if (path === '/api/scans/' + sourceId) value = source;
  else if (path.startsWith('/api/scans/' + sourceId + '/results')) { const query = new URL(path, 'http://local').searchParams.get('q'); value = { total: query === 'support' ? 1 : 201, items: query === 'support' ? hosts.slice(1) : hosts }; }
  else if (path === '/api/scans/' + sourceId + '/sf-batches') {
    if (options.method === 'POST') {
      const payload = JSON.parse(options.body); sent.push(payload); const n = batches.length + 1;
      const host = payload.hosts ? payload.hosts[0] : 'support.example.com';
      const scan = { id: String(n).repeat(32), url: 'https://' + host, status: n === 1 ? 'completed' : 'running', verdict: n === 1 ? 'salesforce' : null, is_salesforce: n === 1, count: 0, options: {}, created: 1, started: 1, finished: n === 1 ? 2 : null };
      value = { id: String(n + 5).repeat(32), source_scan_id: sourceId, source_domain: 'example.com', created: n, started: 1, finished: n === 1 ? 2 : null, status: scan.status,
        total: 1, done: n === 1 ? 1 : 0, salesforce: n === 1 ? 1 : 0, leaking: 0, failed: 0, timed_out: 0, interrupted: 0, cancelled: 0, query: payload.q || '', cancel_requested: false, items: [scan] };
      batches.unshift(value);
    } else value = batches.map(summary);
  } else if (path.startsWith('/api/sf-batches/')) {
    const id = path.split('/')[3]; value = batches.find(b => b.id === id); assert(value);
    if (path.endsWith('/cancel')) { value.status = 'cancelled'; value.cancel_requested = true; value.cancelled = 1; value.done = 1; value.items[0].status = 'cancelled'; }
  } else if (path.includes('/findings?')) value = { total: 0, items: [] };
  else if (path.startsWith('/api/sf-scans/')) { value = batches.flatMap(b => b.items).find(s => s.id === path.split('/')[3]); assert(value); }
  else throw new Error('Unexpected API path ' + path);
  return { ok: true, json: async () => structuredClone(value) };
}
const timers = new Map(); let timerId = 0;
const win = { scrollTo() {}, addEventListener() {}, history: { pushState(_, __, url) { const parsed = new URL(url, 'http://local'); location.pathname = parsed.pathname; location.search = parsed.search; }, replaceState(...args) { this.pushState(...args); } } };
const context = vm.createContext({ document: doc, window: win, location, fetch, URL, URLSearchParams, console, matchMedia: () => ({ matches: true }), navigator: {}, confirm: () => true,
  setInterval() {}, clearTimeout(id) { timers.delete(id); }, setTimeout(cb, delay) { const id = ++timerId; timers.set(id, { cb, delay }); return id; },
  SUBDOMAINS: { path: '/tools/subdomains', name: 'Subdomain Finder' }, SALESFORCE: { path: '/tools/salesforce', name: 'Salesforce Detector' }, renderToolDirectory() {}, toolName: x => x });
const code = fs.readFileSync(root + '/app/static/app.js', 'utf8').replace(/^import .*;$/m, '');
vm.runInContext(code, context);
async function settle() { for (let i = 0; i < 30; i++) await new Promise(resolve => setImmediate(resolve)); }
(async () => {
  await settle(); assert.match(doc.title, /Subdomain Finder/); assert.equal(elements['result-rows'].children.length, 2);
  assert.equal(elements['sf-scan-matching'].disabled, true, 'large all-matching batch must be disabled');
  const checkbox = elements['result-rows'].children[0].children[0].children[0].children[0];
  checkbox.checked = true; await checkbox.fire('change'); assert.equal(elements['sf-scan-selected'].disabled, false);
  await elements['sf-scan-selected'].fire('click'); await settle(); assert.deepEqual(sent[0].hosts, ['api.example.com']);
  assert.match(elements['sf-batch-progress'].textContent, /1 of 1 hosts finished/); assert.equal(elements['sf-scan-selected'].disabled, true);
  elements.filter.value = 'support'; await elements.filter.fire('input');
  for (const [id, t] of [...timers]) if (t.delay === 200) { timers.delete(id); await t.cb(); }
  await settle(); assert.equal(elements['sf-scan-matching'].disabled, false);
  await elements['sf-scan-matching'].fire('click'); await settle(); assert.equal(sent[1].q, 'support'); assert(!('hosts' in sent[1]));
  assert.equal(elements['sf-scan-selected'].disabled, true, 'active batch blocks another launch');
  await elements['sf-batch-cancel'].fire('click'); await settle(); assert.equal(elements['sf-batch-cancel'].hidden, true);
  const open = elements['sf-batch-rows'].children[0].children[3].children[0]; await open.fire('click'); await settle();
  assert.equal(location.pathname, '/tools/salesforce'); assert.match(elements['sf-target'].textContent, /support.example.com/);
  console.log('PASS: HTML ids, module startup, >100 limit, selected-host payload, filtered payload, batch progress, cancellation and Open result navigation. DOM simulation only; no rendered layout assertion.');
})().catch(error => { console.error(error); process.exitCode = 1; });
