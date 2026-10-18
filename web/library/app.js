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
    clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren(); $('coverage').textContent = '';
    $('count').textContent = ''; $('page-position').textContent = ''; $('library').hidden = true; $('login').hidden = false;
    $('lock').disabled = true; $('token').value = ''; notice(message); $('token').focus();
  }
  async function rpc(body) {
    const current = ++epoch; if (controller) controller.abort(); controller = new AbortController();
    try {
    const response = await fetch('/api/library', {method:'POST', headers:{'Authorization':`Bearer ${token}`, 'Content-Type':'application/json'}, body:JSON.stringify(body), credentials:'omit', cache:'no-store', signal:controller.signal});
    if (current !== epoch) return null;
    if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? 'Access unavailable or revoked. Reconnect with an authorized reader.' : 'The reader could not verify this request. Reconnect to retry.');
    const value = await response.json(); if (current !== epoch) return null; return value;
    } catch (error) { if (current !== epoch) return null; throw error; }
  }
  function run(fn) { Promise.resolve().then(fn).catch(error => { if (error.name !== 'AbortError') lock(error.message); }); }
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
    hexadecimal = value.utf8 === null || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value.utf8);
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
  $('connect').addEventListener('submit', event => {
    event.preventDefault(); token = $('token').value; $('token').value = '';
    run(async () => {
      notice('Checking scope access…'); const value = await rpc({action:'catalog'}); if (!value) return;
      if (value.version !== 1) throw new Error('Unsupported reader version.');
      scopes = value.scopes; $('scope').replaceChildren();
      for (const scope of scopes) { const option = document.createElement('option'); option.value = scope.scope; option.textContent = scope.scope; $('scope').append(option); }
      $('login').hidden = true; $('library').hidden = false; $('lock').disabled = false;
      if (!scopes.length) { notice('No currently authorized scopes.'); return; }
      $('scope').value = scopes[0].scope; pin = scopes[0].pin; history = []; await page(0);
    });
  });
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
