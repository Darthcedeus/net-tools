'use strict';
const $ = (id) => document.getElementById(id);
const state = { csrf: null, selected: null, history: [], tab: 'discovery', offset: 0, total: 0, query: '', authenticated: false, generation: 0, engine: false, busy: false };
const active = (scan) => scan && ['queued', 'running'].includes(scan.status);
const statuses = { completed: 'Completed', running: 'Discovering', queued: 'Queued', cancelled: 'Cancelled', failed: 'Failed', timed_out: 'Timed out', interrupted: 'Interrupted', limited: 'Result limit reached' };
let filterTimer, toastTimer;

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
}
function showWorkspace() {
  state.authenticated = true; $('boot').hidden = true; $('login-view').hidden = true; $('workspace').hidden = false; $('navigation').hidden = false; $('logout').hidden = false;
  $('start').disabled = !state.engine;
  message('app-error', state.engine ? '' : 'The Subfinder engine is unavailable. Start this application with Docker to install it.');
}
function setTab(tab) {
  state.tab = tab;
  for (const name of ['discovery', 'history']) {
    $(name + '-view').hidden = name !== tab;
    $(name + '-tab').classList.toggle('selected', name === tab);
    if (name === tab) $(name + '-tab').setAttribute('aria-current', 'page');
    else $(name + '-tab').removeAttribute('aria-current');
  }
  document.title = `Subfinder · ${tab === 'discovery' ? 'Discovery' : 'History'}`;
  if (tab === 'history') refreshHistory().catch(reportError);
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
function paintScan() {
  const scan = state.selected;
  $('scan-summary').hidden = !scan; $('scan-status').hidden = !scan; $('result-tools').hidden = !scan;
  if (!scan) { $('result-table').hidden = true; $('pagination').hidden = true; $('empty').hidden = false; return; }
  $('scan-status').className = 'status ' + scan.status; $('scan-status').textContent = statuses[scan.status] || scan.status;
  $('scan-domain').textContent = scan.domain;
  $('scan-stats').textContent = `${scan.count.toLocaleString()} subdomain${scan.count === 1 ? '' : 's'} · ${elapsed(scan)}`;
  $('cancel').hidden = !active(scan); $('rerun').hidden = active(scan);
  message('scan-note', scan.error || (scan.status === 'queued' ? 'Your scan is queued and will start when the current scan finishes.' : scan.status === 'running' ? 'Discovery is running. You can leave this page; results will be saved on your server.' : ''));
}
async function selectScan(scan) {
  state.generation++; state.selected = scan; state.offset = 0; state.query = ''; $('filter').value = '';
  $('cancel').disabled = false; $('cancel').textContent = 'Cancel scan';
  setTab('discovery'); paintScan(); await refreshResults();
}
async function refreshResults() {
  if (!state.selected || !state.authenticated) return;
  const id = state.selected.id, generation = state.generation, offset = state.offset, query = state.query;
  const [scan, results] = await Promise.all([api(`/api/scans/${id}`), api(`/api/scans/${id}/results?offset=${offset}&q=${encodeURIComponent(query)}`)]);
  if (generation !== state.generation || id !== state.selected?.id || offset !== state.offset || query !== state.query) return;
  state.selected = scan; state.total = results.total; paintScan();
  if (results.total && offset >= results.total) { state.offset = 0; return refreshResults(); }
  const fragment = document.createDocumentFragment();
  for (const item of results.items) {
    const row = document.createElement('tr'), host = document.createElement('td'), sources = document.createElement('td'), list = document.createElement('div');
    host.textContent = item.host; list.className = 'source-list';
    for (const source of item.sources) { const label = document.createElement('span'); label.className = 'source'; label.textContent = source; list.append(label); }
    sources.append(list); row.append(host, sources); fragment.append(row);
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
async function refreshHistory() {
  const history = await api('/api/scans'); if (!state.authenticated) return;
  state.history = history; const fragment = document.createDocumentFragment();
  for (const scan of history) {
    const row = document.createElement('div'), open = document.createElement('button'), domain = document.createElement('span'), meta = document.createElement('span'), remove = document.createElement('button');
    row.className = 'history-row'; open.className = 'history-open'; domain.className = 'history-domain mono'; meta.className = 'history-meta';
    domain.textContent = scan.domain; meta.textContent = `${new Date(scan.created * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })} · ${scan.count.toLocaleString()} subdomains · ${elapsed(scan)}`;
    open.append(domain, meta); open.addEventListener('click', () => selectScan(scan).catch(reportError));
    remove.className = 'history-delete'; remove.textContent = '×'; remove.setAttribute('aria-label', `Delete scan for ${scan.domain}`); remove.title = 'Delete scan'; remove.disabled = active(scan);
    remove.addEventListener('click', async () => {
      if (!confirm(`Delete this scan for ${scan.domain} and its results?`)) return;
      try { await api(`/api/scans/${scan.id}`, { method: 'DELETE' }); if (state.selected?.id === scan.id) { state.selected = null; state.generation++; paintScan(); $('empty').querySelector('h3').textContent = 'A clearer picture starts here.'; $('empty').querySelector('p').textContent = 'Enter a domain above to discover its subdomains.'; message('scan-note', ''); } await refreshHistory(); toast('Scan deleted.'); } catch (error) { reportError(error); }
    });
    row.append(open, statusElement(scan), remove); fragment.append(row);
  }
  $('history-list').replaceChildren(fragment); $('history-empty').hidden = !!history.length;
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('login-button').disabled = true; message('login-error', '');
  try {
    const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('password').value }) });
    state.csrf = data.csrf; $('password').value = ''; const session = await api('/api/session'); state.engine = session.engine_available; showWorkspace(); await refreshHistory();
    if (state.history.length) await selectScan(state.history[0]);
  } catch (error) { message('login-error', error.message); } finally { $('login-button').disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('/api/logout', { method: 'POST', body: '{}' }); state.selected = null; state.history = []; state.query = ''; state.offset = 0; $('filter').value = ''; paintScan(); message('scan-note', ''); showLogin(); } catch (error) { reportError(error); } });
$('discovery-tab').addEventListener('click', () => setTab('discovery'));
$('history-tab').addEventListener('click', () => setTab('history'));
$('first-scan').addEventListener('click', () => { setTab('discovery'); $('domain').focus(); });
$('refresh-history').addEventListener('click', () => refreshHistory().catch(reportError));
$('scan-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('start').disabled = true; message('app-error', '');
  const options = { domain: $('domain').value, max_time: Number($('max-time').value), timeout: Number($('timeout').value), rate_limit: Number($('rate-limit').value), all_sources: $('all-sources').checked, recursive: $('recursive').checked };
  try { const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify(options) }); $('domain').value = scan.domain; await selectScan(scan); await refreshHistory(); }
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
async function poll() {
  if (state.busy || !state.authenticated || document.hidden) return;
  state.busy = true;
  try { if (state.tab === 'discovery' && active(state.selected)) await refreshResults(); if (state.tab === 'history' || state.history.some(active)) await refreshHistory(); }
  catch (error) { reportError(error); } finally { state.busy = false; }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
setInterval(poll, 2000);
(async () => {
  try {
    const session = await api('/api/session'); if (!session.authenticated) return showLogin();
    state.csrf = session.csrf; state.engine = session.engine_available; showWorkspace(); await refreshHistory(); if (state.history.length) await selectScan(state.history[0]);
  } catch (error) { if (!state.authenticated) { showLogin(); message('login-error', 'Could not reach the server. Refresh to reconnect.'); } else reportError(error); }
})();
