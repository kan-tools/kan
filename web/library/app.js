(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let token = '', epoch = 0, controller, scopes = [], pin, after = 0, next = null, history = [], selected = null, source = null, hexadecimal = false;
  const buttons = new Map(), exports = new Map();
  function releaseExport(url) { clearTimeout(exports.get(url)); exports.delete(url); URL.revokeObjectURL(url); }
  function notice(text, error = false) { $('notice').textContent = text; $('notice').className = `notice${error ? ' error' : ''}`; }
  function clearInspector() {
    source = null; selected = null; $('inspection').hidden = true; $('source').textContent = '';
    $('provenance').replaceChildren(); $('range').textContent = ''; $('selection').textContent = 'Select an occurrence';
    $('source-hint').textContent = 'Read exact retained bytes alongside their provenance.'; $('close-inspector').hidden = true;
    for (const button of buttons.values()) button.setAttribute('aria-pressed', 'false');
  }
  function lock(message = 'Locked · connect to browse authorized evidence.') {
    for (const url of exports.keys()) releaseExport(url);
    epoch++; if (controller) controller.abort(); controller = null; token = ''; scopes = []; pin = null; history = []; after = 0; next = null;
    clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren(); $('capability-list').replaceChildren(); $('coverage').textContent = '';
    $('catalog-status').textContent = ''; $('count').textContent = ''; $('page-position').textContent = ''; $('library').hidden = true; $('login').hidden = false;
    $('lock').disabled = true; $('token').value = ''; notice(message); $('token').focus();
  }
  async function rpc(body) {
    const current = ++epoch; if (controller) controller.abort(); controller = new AbortController();
    try {
    const response = await fetch('/api/library', {method:'POST', headers:{'Authorization':`Bearer ${token}`, 'Content-Type':'application/json'}, body:JSON.stringify(body), credentials:'omit', cache:'no-store', signal:controller.signal});
    if (current !== epoch) return null;
    if (!response.ok) {
      const denied = response.status === 401 || response.status === 403;
      const message = denied ? 'Access unavailable or revoked. Reconnect with an authorized reader.' : response.status === 404
        ? 'Retained source is unavailable for this request. Choose another occurrence or refresh the snapshot.'
        : 'This response could not be verified. Retry, refresh the snapshot, or choose another scope.';
      const error = new Error(message); error.accessDenied = denied; error.readerMessage = message; throw error;
    }
    const value = await response.json(); if (current !== epoch) return null; return value;
    } catch (error) { if (current !== epoch) return null; throw error; }
  }
  function run(fn) { Promise.resolve().then(fn).catch(error => {
    if (error.name === 'AbortError') return;
    const message = error.readerMessage || 'Reader unavailable. Retry, refresh the snapshot, or choose another scope.';
    if (error.accessDenied || $('library').hidden) lock(message);
    else { clearInspector(); if (!pin) { $('capability-list').replaceChildren(); $('scope').replaceChildren(); $('catalog-status').textContent = 'Source check failed · coverage is unknown. Retry sources.'; $('catalog-status').className = ''; } notice(message, true); }
  }); }
  function tab(name) {
    $('source-panel').hidden = name !== 'source'; $('provenance').hidden = name !== 'provenance';
    $('source-tab').setAttribute('aria-pressed', String(name === 'source')); $('provenance-tab').setAttribute('aria-pressed', String(name === 'provenance'));
  }
  function renderBytes() {
    if (!source) return;
    const end = source.offset + source.bytes_hex.length / 2;
    $('range').textContent = `Bytes ${source.offset}–${end} of ${source.total_bytes} · ${hexadecimal ? 'hex' : 'UTF-8'} · end exclusive`;
    $('source').textContent = hexadecimal ? source.bytes_hex : source.utf8;
    $('encoding').textContent = hexadecimal ? 'Show UTF-8' : 'Show hex';
    $('encoding').disabled = source.utf8 === null;
  }
  function showSource(value) {
    source = value; $('inspection').hidden = false; $('close-inspector').hidden = false;
    $('selection').textContent = `Occurrence ${value.record.sequence}`;
    $('source-hint').textContent = value.content_trust;
    hexadecimal = value.utf8 === null || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(value.utf8);
    renderBytes(); $('more').disabled = value.next === null;
    $('provenance').replaceChildren();
    for (const [key, val] of Object.entries({Scope:value.scope, Manifest:value.record.manifest, Receipt:value.record.receipt, 'Observed writer':value.writer, Observer:'Not normalized in this source view', 'Claimed speaker':'Not inferred from the writer key', 'Service issuer':value.service_issuer, Signature:value.signature, Admission:value.admission, 'Content trust':value.content_trust})) {
      const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = key; dd.textContent = val; $('provenance').append(dt); $('provenance').append(dd);
    }
    notice('Source verified · this is one retained occurrence, not a reconstructed session.');
  }
  async function inspect(sequence, offset = 0) {
    clearInspector(); selected = sequence; const button = buttons.get(sequence); if (button) button.setAttribute('aria-pressed','true');
    notice('Verifying snapshot membership and reading source…');
    const value = await rpc({action:'source', pin, sequence, offset, length:65536}); if (!value) return;
    showSource(value); tab('source'); $('source-tab').focus();
  }
  async function page(position) {
    clearInspector(); buttons.clear(); $('rows').replaceChildren();
    $('count').textContent = ''; $('coverage').textContent = ''; $('page-position').textContent = 'Loading…';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    notice('Reading the selected snapshot…');
    const value = await rpc({action:'page', pin, after:position, limit:20}); if (!value) return;
    after = position; next = value.next; buttons.clear(); $('rows').replaceChildren();
    for (const row of value.records) {
      const button = document.createElement('button'); button.className = 'occurrence'; button.setAttribute('aria-pressed','false');
      const title = document.createElement('strong'), id = document.createElement('span'); title.textContent = `Occurrence ${row.sequence}`; id.textContent = row.manifest;
      button.append(title); button.append(id); button.addEventListener('click', () => run(() => inspect(row.sequence))); buttons.set(row.sequence,button); $('rows').append(button);
    }
    $('count').textContent = `${value.through} at snapshot`; $('coverage').textContent = value.coverage;
    $('page-position').textContent = value.records.length ? `${value.records[0].sequence}–${value.records[value.records.length-1].sequence}` : '0 entries';
    $('empty').hidden = value.records.length !== 0; $('previous').disabled = history.length === 0; $('next').disabled = next === null;
    notice('Snapshot pinned · refresh the snapshot to include newer entries.');
  }
  function renderCapabilities(value) {
    if (!Array.isArray(value.capabilities) || !Array.isArray(value.unavailable)) throw new Error('Unsupported capability response.');
    const labels = {'snapshot-inventory':'Snapshot inventory','source-ranges':'Source ranges','provenance':'Provenance','semantic-search':'Search','normalized-sessions':'Sessions','annotations':'Annotations','saved-views':'Saved views','analysis':'Analysis','administrative-jobs':'Admin jobs'};
    const supported = new Set(['snapshot-inventory','source-ranges','provenance']), seen = new Set();
    $('capability-list').replaceChildren();
    for (const [items, available] of [[value.capabilities,true],[value.unavailable,false]]) {
      for (const capability of items) {
        if (typeof capability !== 'string' || seen.has(capability)) throw new Error('Inconsistent capability response.');
        seen.add(capability);
        const row = document.createElement('div'), name = document.createElement('dt'), state = document.createElement('dd');
        name.textContent = labels[capability] || capability;
        state.textContent = available ? (supported.has(capability) ? 'Available' : 'Client unsupported') : 'Upcoming';
        state.className = available && supported.has(capability) ? 'available' : '';
        row.append(name); row.append(state); $('capability-list').append(row);
      }
    }
  }
  function validateScopes(value) {
    const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
    if (!Array.isArray(value) || value.length > 16) throw new Error('Invalid scope catalog.');
    const seen = new Set();
    for (const entry of value) {
      if (!object(entry) || typeof entry.scope !== 'string' || !entry.scope.length || entry.scope.length > 256 || seen.has(entry.scope)
          || !object(entry.pin) || typeof entry.pin.request !== 'string' || !entry.pin.request.length || entry.pin.request.length > 8192 || !object(entry.pin.reply)) {
        throw new Error('Invalid or duplicate scope entry.');
      }
      seen.add(entry.scope);
    }
  }
  async function catalog() {
    clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren();
    scopes = []; pin = null; history = []; after = 0; next = null;
    $('coverage').textContent = ''; $('count').textContent = ''; $('page-position').textContent = '';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    $('capability-list').replaceChildren(); $('catalog-status').textContent = 'Checking configured sources…';
    notice('Checking scope access…');
    const value = await rpc({action:'catalog'}); if (!value) return;
    if (value.version !== 1 || !['complete','partial'].includes(value.coverage)) throw new Error('Unsupported reader version or coverage.');
    validateScopes(value.scopes);
    renderCapabilities(value);
    scopes = value.scopes;
    for (const scope of scopes) { const option = document.createElement('option'); option.value = scope.scope; option.textContent = scope.scope; $('scope').append(option); }
    $('login').hidden = true; $('library').hidden = false; $('lock').disabled = false;
    const partial = value.coverage === 'partial';
    $('catalog-status').className = partial ? 'partial' : '';
    $('catalog-status').textContent = partial
      ? 'Partial coverage · some configured sources could not be verified. Available scopes remain browsable. Retry sources to check again.'
      : 'Source checks complete · only currently authorized scopes are shown.';
    if (!scopes.length) {
      notice(partial ? 'No verified scope is available from this incomplete check. Retry sources.' : 'No currently authorized scopes.');
      return;
    }
    $('scope').value = scopes[0].scope; pin = scopes[0].pin; await page(0);
  }
  $('connect').addEventListener('submit', event => {
    event.preventDefault(); token = $('token').value; $('token').value = ''; run(catalog);
  });
  $('retry-sources').addEventListener('click', () => run(catalog));
  $('scope').addEventListener('change', () => run(async () => { const chosen = scopes.find(s => s.scope === $('scope').value); if (!chosen) return; pin = chosen.pin; history = []; await page(0); }));
  $('resnapshot').addEventListener('click', () => run(async () => { if (!pin) return; clearInspector(); const value = await rpc({action:'snapshot',scope:$('scope').value}); if (!value) return; pin = value.pin; const chosen = scopes.find(s => s.scope === $('scope').value); chosen.pin = pin; history = []; await page(0); }));
  $('next').addEventListener('click', () => run(async () => { if (next === null) return; history.push(after); await page(next); }));
  $('previous').addEventListener('click', () => run(async () => { if (history.length) await page(history.pop()); }));
  $('more').addEventListener('click', () => run(async () => { if (source && source.next !== null) await inspect(selected,source.next); }));
  $('download').addEventListener('click', () => run(async () => {
    if (!source) return; const offset = source.offset, sequence = selected;
    // Export rechecks authorization; the displayed range is not an offline grant.
    const value = await rpc({action:'source',pin,sequence,offset,length:65536}); if (!value) return;
    const bytes = new Uint8Array(value.bytes_hex.match(/../g)?.map(x => parseInt(x,16)) || []);
    const url = URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));
    // Keep the URL alive for navigation to begin; lock/pagehide release it early.
    exports.set(url, setTimeout(() => releaseExport(url), 1000));
    const a = document.createElement('a'); a.href = url; a.download = `kan-occurrence-${sequence}-offset-${offset}.bin`;
    a.hidden = true; document.body.append(a); a.click(); a.remove();
  }));
  $('encoding').addEventListener('click', () => { if (source && source.utf8 !== null) { hexadecimal = !hexadecimal; renderBytes(); } });
  $('source-tab').addEventListener('click', () => tab('source')); $('provenance-tab').addEventListener('click', () => tab('provenance'));
  $('close-inspector').addEventListener('click', () => { epoch++; if(controller) controller.abort(); const button = buttons.get(selected); clearInspector(); if(button)button.focus(); });
  $('lock').addEventListener('click', () => lock());
  window.addEventListener('pagehide', () => lock());
})();
