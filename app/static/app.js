'use strict';
import { SUBDOMAINS, SALESFORCE, renderToolDirectory, toolName } from './tools.js';

const $ = (id) => document.getElementById(id);
const state = {
  csrf: null, authenticated: false, generation: 0, engine: false, busy: false, tab: 'home',
  selected: null, offset: 0, total: 0, query: '',
  sfSelected: null, sfOffset: 0, sfTotal: 0, sfQuery: '', sfReadable: false,
  activity: [],
};
const ROUTES = { home: '/', discovery: SUBDOMAINS.path, salesforce: SALESFORCE.path, history: '/activity' };
const PAGE_TITLES = { home: 'Home', discovery: SUBDOMAINS.name, salesforce: SALESFORCE.name, history: 'Activity' };
const active = (scan) => scan && ['queued', 'running'].includes(scan.status);
const statuses = { completed: 'Completed', running: 'Scanning', queued: 'Queued', cancelled: 'Cancelled', failed: 'Failed', timed_out: 'Timed out', interrupted: 'Interrupted', limited: 'Result limit reached' };
const verdicts = { leaking: 'Leaking', salesforce: 'Salesforce', not_salesforce: 'Not Salesforce' };
const verdictClass = { leaking: 'verdict-leaking', salesforce: 'verdict-ok', not_salesforce: 'verdict-none' };
let filterTimer, sfFilterTimer, toastTimer;

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf || '', ...options.headers } });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/login') showLogin();
    throw new Error(data.error || 'The request failed. Try again.');
  }
  return data;
}

function message(id, text) { $(id).textContent = text || ''; $(id).hidden = !text; }
function toast(text) { message('toast', text); clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3500); }
function showLogin() {
  state.authenticated = false; state.csrf = null; state.generation++;
  $('boot').hidden = true; $('workspace').hidden = true; $('navigation').hidden = true; $('logout').hidden = true; $('login-view').hidden = false;
  $('password').value = ''; $('password').focus();
  document.title = 'Net Tools · Sign in';
}
function showWorkspace() {
  state.authenticated = true; $('boot').hidden = true; $('login-view').hidden = true; $('workspace').hidden = false; $('navigation').hidden = false; $('logout').hidden = false;
  $('start').disabled = !state.engine;
  message('app-error', state.engine ? '' : 'The Subfinder engine is unavailable. Start this application with Docker to install it.');
  setTab(routeFromLocation(), { navigation: 'replace', focus: false, scanId: scanIdFromLocation(), load: false });
}

function routeFromLocation() {
  const path = location.pathname.replace(/\/+$/, '') || '/';
  return Object.keys(ROUTES).find((tab) => ROUTES[tab] === path) || 'home';
}
function scanIdFromLocation() {
  const id = new URLSearchParams(location.search).get('scan');
  return id && /^[a-f0-9]{32}$/.test(id) ? id : null;
}
function setTab(tab, { navigation = 'push', focus = true, scanId = null, load = true } = {}) {
  if (!Object.hasOwn(ROUTES, tab)) return;
  state.tab = tab;
  for (const name of Object.keys(ROUTES)) {
    $(name + '-view').hidden = name !== tab;
    $(name + '-tab').classList.toggle('selected', name === tab);
    if (name === tab) $(name + '-tab').setAttribute('aria-current', 'page');
    else $(name + '-tab').removeAttribute('aria-current');
  }
  document.title = `Net Tools · ${PAGE_TITLES[tab]}`;
  const carries = tab === 'discovery' || tab === 'salesforce';
  const path = ROUTES[tab] + (carries && scanId ? `?scan=${scanId}` : '');
  if (navigation !== 'none' && location.pathname + location.search !== path) {
    window.history[navigation === 'replace' ? 'replaceState' : 'pushState']({}, '', path);
  }
  if (focus) { $(tab + '-view').querySelector('h1').focus({ preventScroll: true }); window.scrollTo(0, 0); }
  if (!load) return;
  if (tab === 'history' || tab === 'home') refreshActivity().catch(reportError);
  else if (tab === 'discovery' && state.selected) refreshResults().catch(reportError);
  else if (tab === 'salesforce' && state.sfSelected) refreshSfResults().catch(reportError);
}

async function resumeWorkspace() {
  const route = location.pathname + location.search, generation = state.generation;
  await refreshActivity();
  if (!state.authenticated || generation !== state.generation || route !== location.pathname + location.search) return;
  const id = scanIdFromLocation();
  if (state.tab === 'salesforce') {
    const scan = id ? await api(`/api/sf-scans/${id}`).catch(() => null) : state.sfSelected;
    if (!guard(generation, route)) return;
    if (scan) { state.sfSelected = scan; state.generation++; paintSfScan(); await refreshSfResults(); }
  } else if (state.tab === 'discovery') {
    const scan = id ? await api(`/api/scans/${id}`).catch(() => null) : state.selected;
    if (!guard(generation, route)) return;
    if (scan) { state.selected = scan; state.generation++; paintScan(); await refreshResults(); }
  }
}
function guard(generation, route) {
  return state.authenticated && generation === state.generation && route === location.pathname + location.search;
}
function reportError(error) { if (state.authenticated) message('app-error', error.message || 'Could not connect. Try again.'); }
function statusElement(scan) {
  const element = document.createElement('span'); element.className = 'status ' + scan.status; element.textContent = statuses[scan.status] || scan.status; return element;
}
function elapsed(scan) {
  if (!scan.started) return 'Waiting to start';
  const seconds = Math.max(0, Math.round((scan.finished || Date.now() / 1000) - scan.started));
  return seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
}

/* ---- Subdomain Finder --------------------------------------------------- */

function paintScan() {
  const scan = state.selected;
  $('scan-summary').hidden = !scan; $('scan-status').hidden = !scan; $('result-tools').hidden = !scan;
  if (!scan) { $('result-table').hidden = true; $('pagination').hidden = true; $('empty').hidden = false; return; }
  $('scan-status').className = 'status ' + scan.status; $('scan-status').textContent = statuses[scan.status] || scan.status;
  $('scan-domain').textContent = scan.domain;
  $('scan-stats').textContent = `${scan.count.toLocaleString()} subdomain${scan.count === 1 ? '' : 's'} · ${elapsed(scan)}`;
  $('cancel').hidden = !active(scan); $('rerun').hidden = active(scan);
  message('scan-note', scan.error || (scan.status === 'queued' ? 'Your scan is queued and will start when the current scan finishes.' : scan.status === 'running' ? 'Discovery and IP lookups are running. You can leave this page; results will be saved on your server.' : ''));
}
async function selectScan(scan) {
  state.generation++; state.selected = scan; state.offset = 0; state.query = ''; $('filter').value = '';
  $('cancel').disabled = false; $('cancel').textContent = 'Cancel scan';
  setTab('discovery', { scanId: scan.id, load: false }); paintScan(); await refreshResults();
}
async function refreshResults() {
  if (!state.selected || !state.authenticated) return;
  const id = state.selected.id, generation = state.generation, offset = state.offset, query = state.query;
  const scan = await api(`/api/scans/${id}`);
  const results = await api(`/api/scans/${id}/results?offset=${offset}&q=${encodeURIComponent(query)}`);
  if (generation !== state.generation || id !== state.selected?.id || offset !== state.offset || query !== state.query) return;
  state.selected = scan; state.total = results.total; paintScan();
  if (results.total && offset >= results.total) { state.offset = 0; return refreshResults(); }
  const fragment = document.createDocumentFragment();
  for (const item of results.items) {
    const row = document.createElement('tr'), host = document.createElement('td'), sources = document.createElement('td'), list = document.createElement('div');
    host.textContent = item.host; list.className = 'source-list';
    const addresses = document.createElement('td'); addresses.className = 'ip-cell'; addresses.dataset.label = 'IP addresses';
    for (const ip of item.ips || []) {
      const value = document.createElement('div'); value.className = 'ip-address';
      const groups = ip.split(':');
      groups.forEach((group, index) => { value.append(document.createTextNode(group)); if (index < groups.length - 1) value.append(document.createTextNode(':'), document.createElement('wbr')); });
      addresses.append(value);
    }
    const dnsLabels = { pending: 'Resolving…', no_records: 'No A/AAAA records', timeout: 'Lookup timed out', error: 'Lookup failed', cancelled: 'Lookup cancelled', not_checked: 'Not checked · rerun scan', partial: 'Some lookups failed' };
    if (!(item.ips || []).length || item.dns_status === 'partial') { const note = document.createElement('span'); note.className = 'dns-note'; note.textContent = dnsLabels[item.dns_status] || 'Not checked · rerun scan'; addresses.append(note); }
    sources.dataset.label = 'Sources';
    for (const source of item.sources) { const label = document.createElement('span'); label.className = 'source'; label.textContent = source; list.append(label); }
    sources.append(list); row.append(host, addresses, sources); fragment.append(row);
  }
  $('result-rows').replaceChildren(fragment);
  $('result-table').hidden = !results.items.length; $('empty').hidden = !!results.items.length;
  if (!results.items.length) {
    $('empty').querySelector('h3').textContent = query ? 'No matching subdomains.' : active(scan) ? 'Looking beneath the surface…' : 'No subdomains found.';
    $('empty').querySelector('p').textContent = query ? 'Try a different filter to see more results.' : active(scan) ? 'Results will appear as passive sources return them.' : 'Try all sources or add provider API keys for broader coverage. Passive results do not confirm that a host is live.';
  }
  $('copy').disabled = !results.total; $('export').disabled = !results.total;
  $('pagination').hidden = !results.total;
  $('page-label').textContent = `${(offset + 1).toLocaleString()}–${(offset + results.items.length).toLocaleString()} of ${results.total.toLocaleString()}${query ? ' matching' : ''} subdomains`;
  $('previous').disabled = offset === 0; $('next').disabled = offset + 200 >= results.total;
}

/* ---- Salesforce Detector ------------------------------------------------ */

function sfTargetHost(url) { try { return new URL(url).host; } catch { return url; } }
function paintSfScan() {
  const scan = state.sfSelected;
  $('sf-summary').hidden = !scan; $('sf-status').hidden = !scan; $('sf-tools').hidden = !scan;
  if (!scan) { $('sf-table').hidden = true; $('sf-pagination').hidden = true; $('sf-empty').hidden = false; $('sf-verdict').hidden = true; return; }
  $('sf-status').className = 'status ' + scan.status; $('sf-status').textContent = statuses[scan.status] || scan.status;
  $('sf-target').textContent = sfTargetHost(scan.url);
  const noun = `${scan.count.toLocaleString()} readable object${scan.count === 1 ? '' : 's'}`;
  $('sf-stats').textContent = `${noun} · ${elapsed(scan)}`;
  $('sf-cancel').hidden = !active(scan); $('sf-rerun').hidden = active(scan);
  const details = scan.details || {};
  const finished = !active(scan);
  if (finished && scan.verdict) {
    const label = verdicts[scan.verdict] || scan.verdict;
    const parts = [];
    if (scan.verdict === 'leaking') parts.push(`Guest access is leaking data — ${noun} readable.`);
    else if (scan.verdict === 'salesforce') parts.push('Salesforce Aura detected; no guest-readable objects found.');
    else parts.push('No Salesforce Aura endpoint detected.');
    if (scan.aura_endpoint) parts.push(`Aura endpoint: ${scan.aura_endpoint}`);
    if (details.self_registration) parts.push('Self-registration appears enabled.');
    $('sf-verdict').className = 'notice ' + (verdictClass[scan.verdict] || '');
    $('sf-verdict').textContent = `${label}. ${parts.join(' ')}`;
    $('sf-verdict').hidden = false;
  } else {
    $('sf-verdict').hidden = true;
  }
  message('sf-note', scan.error || (scan.status === 'queued' ? 'Your scan is queued and will start when the current scan finishes.' : scan.status === 'running' ? 'Fingerprinting the site and probing guest access. You can leave this page; results are saved on your server.' : ''));
}
async function selectSfScan(scan) {
  state.generation++; state.sfSelected = scan; state.sfOffset = 0; state.sfQuery = ''; state.sfReadable = false;
  $('sf-filter').value = ''; $('sf-readable').checked = false;
  $('sf-cancel').disabled = false; $('sf-cancel').textContent = 'Cancel scan';
  setTab('salesforce', { scanId: scan.id, load: false }); paintSfScan(); await refreshSfResults();
}
async function refreshSfResults() {
  if (!state.sfSelected || !state.authenticated) return;
  const id = state.sfSelected.id, generation = state.generation, offset = state.sfOffset, query = state.sfQuery, readable = state.sfReadable;
  const scan = await api(`/api/sf-scans/${id}`);
  const results = await api(`/api/sf-scans/${id}/findings?offset=${offset}&readable=${readable ? 1 : 0}&q=${encodeURIComponent(query)}`);
  if (generation !== state.generation || id !== state.sfSelected?.id || offset !== state.sfOffset || query !== state.sfQuery || readable !== state.sfReadable) return;
  state.sfSelected = scan; state.sfTotal = results.total; paintSfScan();
  if (results.total && offset >= results.total) { state.sfOffset = 0; return refreshSfResults(); }
  const fragment = document.createDocumentFragment();
  for (const item of results.items) {
    const row = document.createElement('tr');
    const object = document.createElement('td'); object.className = 'mono'; object.dataset.label = 'Object'; object.textContent = item.object;
    const count = document.createElement('td'); count.dataset.label = 'Records'; count.textContent = item.record_count == null ? '—' : item.record_count.toLocaleString();
    const access = document.createElement('td'); access.dataset.label = 'Guest access';
    const badge = document.createElement('span'); badge.className = 'status ' + (item.readable ? 'leaking' : 'completed'); badge.textContent = item.readable ? 'Readable' : 'No access'; access.append(badge);
    const evidence = document.createElement('td'); evidence.dataset.label = 'Sample evidence';
    if ((item.samples || []).length) {
      const details = document.createElement('details'); const summary = document.createElement('summary');
      summary.textContent = `${item.samples.length} sample${item.samples.length === 1 ? '' : 's'}`; details.append(summary);
      for (const sample of item.samples) {
        const card = document.createElement('div'); card.className = 'sample-card';
        for (const [key, value] of Object.entries(sample)) {
          const field = document.createElement('div'); field.className = 'sample-field';
          const name = document.createElement('span'); name.className = 'sample-key'; name.textContent = key;
          const val = document.createElement('span'); val.className = 'sample-value'; val.textContent = value == null ? '' : value;
          field.append(name, val); card.append(field);
        }
        details.append(card);
      }
      evidence.append(details);
    } else { const dash = document.createElement('span'); dash.className = 'muted'; dash.textContent = '—'; evidence.append(dash); }
    row.append(object, count, access, evidence); fragment.append(row);
  }
  $('sf-rows').replaceChildren(fragment);
  $('sf-table').hidden = !results.items.length; $('sf-empty').hidden = !!results.items.length;
  if (!results.items.length) {
    $('sf-empty').querySelector('h3').textContent = query ? 'No matching objects.' : active(scan) ? 'Scanning…' : scan.is_salesforce ? 'No objects enumerated.' : 'No Salesforce Aura endpoint found.';
    $('sf-empty').querySelector('p').textContent = query ? 'Try a different filter.' : active(scan) ? 'Objects appear here as the guest-access probe runs.' : scan.is_salesforce ? 'The site runs Salesforce Aura but no objects were readable as a guest.' : 'This target does not appear to expose a Salesforce Aura/Lightning endpoint.';
  }
  $('sf-pagination').hidden = !results.total;
  $('sf-page-label').textContent = `${(offset + 1).toLocaleString()}–${(offset + results.items.length).toLocaleString()} of ${results.total.toLocaleString()}${query ? ' matching' : ''} object${results.total === 1 ? '' : 's'}`;
  $('sf-previous').disabled = offset === 0; $('sf-next').disabled = offset + 200 >= results.total;
}

/* ---- Shared activity ---------------------------------------------------- */

function activityMeta(item) {
  if (item.tool === 'salesforce') {
    const verdict = item.verdict && verdicts[item.verdict] ? verdicts[item.verdict] : '';
    return `${toolName(item.tool)}${verdict ? ' · ' + verdict : ''}`;
  }
  return `${toolName(item.tool)}`;
}
function activityCount(item) {
  if (item.tool === 'salesforce') return `${item.count.toLocaleString()} readable object${item.count === 1 ? '' : 's'}`;
  return `${item.count.toLocaleString()} subdomain${item.count === 1 ? '' : 's'}`;
}
function activityBadge(item) {
  if (item.tool === 'salesforce' && !active(item) && item.verdict) {
    const badge = document.createElement('span'); badge.className = 'status ' + (verdictClass[item.verdict] || '');
    badge.textContent = verdicts[item.verdict] || item.verdict; return badge;
  }
  return statusElement(item);
}
async function openActivity(item) {
  try {
    if (item.tool === 'salesforce') { const scan = await api(`/api/sf-scans/${item.id}`); await selectSfScan(scan); }
    else { const scan = await api(`/api/scans/${item.id}`); await selectScan(scan); }
  } catch (error) { reportError(error); }
}
async function deleteActivity(item) {
  const noun = item.tool === 'salesforce' ? 'scan' : 'scan';
  if (!confirm(`Delete this ${toolName(item.tool)} ${noun} for ${item.label} and its results?`)) return;
  const endpoint = item.tool === 'salesforce' ? `/api/sf-scans/${item.id}` : `/api/scans/${item.id}`;
  try {
    await api(endpoint, { method: 'DELETE' });
    if (item.tool === 'salesforce' && state.sfSelected?.id === item.id) { state.sfSelected = null; state.generation++; paintSfScan(); message('sf-note', ''); }
    if (item.tool === 'subdomains' && state.selected?.id === item.id) { state.selected = null; state.generation++; paintScan(); message('scan-note', ''); }
    await refreshActivity(); toast('Scan deleted.');
  } catch (error) { reportError(error); }
}
async function refreshActivity() {
  const items = await api('/api/activity'); if (!state.authenticated) return;
  state.activity = items;
  const list = document.createDocumentFragment();
  for (const item of items) {
    const row = document.createElement('div'), open = document.createElement('button'), label = document.createElement('span'), meta = document.createElement('span'), remove = document.createElement('button');
    row.className = 'history-row'; open.className = 'history-open'; label.className = 'history-domain mono'; meta.className = 'history-meta';
    label.textContent = item.label; meta.textContent = `${activityMeta(item)} · ${formatDate(item.created)} · ${activityCount(item)} · ${elapsed(item)}`;
    open.append(label, meta); open.addEventListener('click', () => openActivity(item));
    remove.className = 'history-delete'; remove.textContent = '×'; remove.setAttribute('aria-label', `Delete ${item.label}`); remove.title = 'Delete scan'; remove.disabled = active(item);
    remove.addEventListener('click', () => deleteActivity(item));
    row.append(open, activityBadge(item), remove); list.append(row);
  }
  $('history-list').replaceChildren(list); $('history-empty').hidden = !!items.length;

  const recent = document.createDocumentFragment();
  for (const item of items.slice(0, 3)) {
    const row = document.createElement('button'), copy = document.createElement('div'), label = document.createElement('span'), meta = document.createElement('span');
    row.className = 'recent-row'; copy.className = 'recent-copy'; label.className = 'history-domain mono'; meta.className = 'history-meta';
    label.textContent = item.label; meta.textContent = `${activityMeta(item)} · ${formatDate(item.created, true)}`; copy.append(label, meta);
    const result = document.createElement('div'), count = document.createElement('span'); result.className = 'recent-result';
    count.className = 'recent-count'; count.textContent = activityCount(item);
    result.append(activityBadge(item), count); row.append(copy, result);
    row.addEventListener('click', () => openActivity(item)); recent.append(row);
  }
  $('recent-list').replaceChildren(recent); $('recent-list').hidden = !items.length; $('recent-empty').hidden = !!items.length;
}

function formatDate(created, compact = false) {
  const options = compact ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' } : { dateStyle: 'medium', timeStyle: 'short' };
  return new Date(created * 1000).toLocaleString(undefined, options);
}

/* ---- Shell wiring ------------------------------------------------------- */

renderToolDirectory($('tool-directory'));
document.addEventListener('click', (event) => {
  const link = event.target.closest('a[data-route]');
  if (!link || !state.authenticated || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault(); setTab(link.dataset.route);
});
window.addEventListener('popstate', () => {
  if (!state.authenticated) return;
  setTab(routeFromLocation(), { navigation: 'none', load: false }); resumeWorkspace().catch(reportError);
});

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('login-button').disabled = true; message('login-error', '');
  try {
    const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('password').value }) });
    state.csrf = data.csrf; $('password').value = ''; const session = await api('/api/session'); state.engine = session.engine_available; showWorkspace(); await resumeWorkspace();
  } catch (error) { message('login-error', error.message); } finally { $('login-button').disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('/api/logout', { method: 'POST', body: '{}' }); state.selected = null; state.sfSelected = null; state.activity = []; state.query = ''; state.offset = 0; state.sfQuery = ''; state.sfOffset = 0; $('filter').value = ''; $('sf-filter').value = ''; paintScan(); paintSfScan(); message('scan-note', ''); message('sf-note', ''); showLogin(); } catch (error) { reportError(error); } });
$('first-scan').addEventListener('click', () => { setTab('discovery'); $('domain').focus(); });
$('refresh-history').addEventListener('click', () => refreshActivity().catch(reportError));

$('scan-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('start').disabled = true; message('app-error', '');
  const options = { domain: $('domain').value, max_time: Number($('max-time').value), timeout: Number($('timeout').value), rate_limit: Number($('rate-limit').value), all_sources: $('all-sources').checked, recursive: $('recursive').checked };
  try { const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify(options) }); $('domain').value = scan.domain; await selectScan(scan); await refreshActivity(); }
  catch (error) { reportError(error); } finally { $('start').disabled = !state.engine; }
});
$('cancel').addEventListener('click', async () => {
  if (!state.selected) return; $('cancel').disabled = true;
  try { await api(`/api/scans/${state.selected.id}/cancel`, { method: 'POST', body: '{}' }); $('cancel').textContent = 'Cancelling…'; await refreshResults(); }
  catch (error) { $('cancel').disabled = false; reportError(error); }
});
$('rerun').addEventListener('click', () => {
  const scan = state.selected; if (!scan) return;
  $('domain').value = scan.domain; $('max-time').value = scan.options.max_time; $('timeout').value = scan.options.timeout; $('rate-limit').value = scan.options.rate_limit; $('all-sources').checked = scan.options.all_sources; $('recursive').checked = scan.options.recursive;
  $('domain').focus(); $('scan-form').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'center' }); toast('Scan options restored. Press Start discovery to run again.');
});
$('filter').addEventListener('input', () => { state.query = $('filter').value.trim(); state.offset = 0; clearTimeout(filterTimer); filterTimer = setTimeout(() => refreshResults().catch(reportError), 200); });
$('previous').addEventListener('click', () => { state.offset = Math.max(0, state.offset - 200); refreshResults().catch(reportError); });
$('next').addEventListener('click', () => { state.offset += 200; refreshResults().catch(reportError); });
$('copy').addEventListener('click', async () => {
  if (!state.selected) return; $('copy').disabled = true;
  try {
    const response = await fetch(`/api/scans/${state.selected.id}/export?format=txt&q=${encodeURIComponent(state.query)}`);
    if (!response.ok) throw new Error('Could not export results. Refresh and try again.');
    await navigator.clipboard.writeText(await response.text()); toast(state.query ? 'Matching subdomains copied.' : 'All subdomains copied.');
  } catch (error) { toast(error.message || 'Clipboard unavailable. Use Export to save your results.'); } finally { $('copy').disabled = !state.total; }
});
$('export').addEventListener('change', async () => {
  const format = $('export').value; $('export').value = ''; if (!format || !state.selected) return;
  const scan = state.selected;
  try {
    const response = await fetch(`/api/scans/${scan.id}/export?format=${format}&q=${encodeURIComponent(state.query)}`);
    if (!response.ok) throw new Error('Could not export results. Refresh and try again.');
    const url = URL.createObjectURL(await response.blob()), anchor = document.createElement('a');
    anchor.href = url; anchor.download = `${scan.domain}-${scan.id.slice(0, 8)}.${format}`; document.body.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); toast('Export downloaded.');
  } catch (error) { reportError(error); }
});

$('sf-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('sf-start').disabled = true; message('app-error', '');
  const options = { url: $('sf-url').value, sample_size: Number($('sf-sample-size').value), max_objects: Number($('sf-max-objects').value) };
  try { const scan = await api('/api/sf-scans', { method: 'POST', body: JSON.stringify(options) }); $('sf-url').value = scan.url; await selectSfScan(scan); await refreshActivity(); }
  catch (error) { reportError(error); } finally { $('sf-start').disabled = false; }
});
$('sf-cancel').addEventListener('click', async () => {
  if (!state.sfSelected) return; $('sf-cancel').disabled = true;
  try { await api(`/api/sf-scans/${state.sfSelected.id}/cancel`, { method: 'POST', body: '{}' }); $('sf-cancel').textContent = 'Cancelling…'; await refreshSfResults(); }
  catch (error) { $('sf-cancel').disabled = false; reportError(error); }
});
$('sf-rerun').addEventListener('click', () => {
  const scan = state.sfSelected; if (!scan) return;
  $('sf-url').value = scan.url; $('sf-sample-size').value = scan.options.sample_size; $('sf-max-objects').value = scan.options.max_objects;
  $('sf-url').focus(); $('sf-form').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'center' }); toast('Options restored. Press Scan site to run again.');
});
$('sf-filter').addEventListener('input', () => { state.sfQuery = $('sf-filter').value.trim(); state.sfOffset = 0; clearTimeout(sfFilterTimer); sfFilterTimer = setTimeout(() => refreshSfResults().catch(reportError), 200); });
$('sf-readable').addEventListener('change', () => { state.sfReadable = $('sf-readable').checked; state.sfOffset = 0; refreshSfResults().catch(reportError); });
$('sf-previous').addEventListener('click', () => { state.sfOffset = Math.max(0, state.sfOffset - 200); refreshSfResults().catch(reportError); });
$('sf-next').addEventListener('click', () => { state.sfOffset += 200; refreshSfResults().catch(reportError); });
$('sf-export').addEventListener('change', async () => {
  const format = $('sf-export').value; $('sf-export').value = ''; if (!format || !state.sfSelected) return;
  const scan = state.sfSelected;
  try {
    const response = await fetch(`/api/sf-scans/${scan.id}/export?format=${format}&q=${encodeURIComponent(state.sfQuery)}`);
    if (!response.ok) throw new Error('Could not export findings. Refresh and try again.');
    const url = URL.createObjectURL(await response.blob()), anchor = document.createElement('a');
    anchor.href = url; anchor.download = `${sfTargetHost(scan.url)}-${scan.id.slice(0, 8)}.${format}`; document.body.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); toast('Export downloaded.');
  } catch (error) { reportError(error); }
});

async function poll() {
  if (state.busy || !state.authenticated || document.hidden) return;
  state.busy = true;
  try {
    if (state.tab === 'discovery' && active(state.selected)) await refreshResults();
    if (state.tab === 'salesforce' && active(state.sfSelected)) await refreshSfResults();
    if (['home', 'history'].includes(state.tab) || state.activity.some(active)) await refreshActivity();
  } catch (error) { reportError(error); } finally { state.busy = false; }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
setInterval(poll, 2000);
(async () => {
  try {
    const session = await api('/api/session'); if (!session.authenticated) return showLogin();
    state.csrf = session.csrf; state.engine = session.engine_available; showWorkspace(); await resumeWorkspace();
  } catch (error) { if (!state.authenticated) { showLogin(); message('login-error', 'Could not reach the server. Refresh to reconnect.'); } else reportError(error); }
})();
