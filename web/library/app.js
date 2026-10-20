(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let token = '', epoch = 0, controller, scopes = [], pin, after = 0, next = null, history = [], selected = null, source = null, hexadecimal = false;
  const selections = new Map();
  let activeSource = null, catalogContent = false;
  const discovered = new Map();
  let scanCursor = null, scanComplete = false, scanCount = 0, discoveryRun = 0;
  const sourceId = entry => entry.id || entry.scope;
  const isProof = () => activeSource?.protocol === 'kan-proof-reader/1';
  const buttons = new Map(), exports = new Map(), contentSelection = new Set(), checks = new Map();
  let attemptMode = false;
  let pinWire = null, contentEnabled = false, contentValue = null, returnItem = null;
  function releaseExport(url) { clearTimeout(exports.get(url)); exports.delete(url); URL.revokeObjectURL(url); }
  function notice(text, error = false) { $('notice').textContent = text; $('notice').className = `notice${error ? ' error' : ''}`; }
  function clearContent(clearSelection = true) {
    contentValue = null; returnItem = null; $('content-panel').replaceChildren(); $('content-tab').disabled = true;
    if (clearSelection) { attemptMode = false; contentSelection.clear(); for (const check of checks.values()) check.checked = false; }
    updateSelection();
  }
  function updateSelection() {
    $('content-count').textContent = `${contentSelection.size} selected`;
    $('interpret').disabled = !contentEnabled || !pinWire || contentSelection.size === 0;
    $('clear-content').disabled = contentSelection.size === 0;
  }
  function cancelWork() { epoch++; if (controller) controller.abort(); }
  function clearInspector() {
    source = null; selected = null; $('download').disabled = true; $('more').disabled = true; $('source-tab').disabled = true; $('provenance-tab').disabled = true; $('inspection').hidden = true; $('source').textContent = '';
    $('provenance').replaceChildren(); $('range').textContent = ''; $('selection').textContent = 'Select an occurrence';
    $('source-hint').textContent = 'Read exact retained bytes alongside their provenance.'; $('close-inspector').hidden = true;
    for (const button of buttons.values()) button.setAttribute('aria-pressed', 'false');
  }
  function lock(message = 'Locked · connect to browse authorized evidence.') {
    for (const url of exports.keys()) releaseExport(url);
    epoch++; if (controller) controller.abort(); controller = null; token = ''; scopes = []; pin = null; history = []; after = 0; next = null;
    pinWire = null; contentEnabled = false; activeSource = null; clearDiscovery(); selections.clear(); clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren(); $('capability-list').replaceChildren(); $('coverage').textContent = '';
    $('catalog-status').textContent = ''; $('count').textContent = ''; $('page-position').textContent = ''; $('library').hidden = true; $('login').hidden = false;
    $('lock').disabled = true; $('token').value = ''; notice(message); $('token').focus();
  }
  async function rpc(body) {
    const current = ++epoch; if (controller) controller.abort(); controller = new AbortController();
    try {
    const response = await fetch(['proof-content','proof-attempt'].includes(body.action) ? `/api/library/${body.action}` : '/api/library', {method:'POST', headers:{'Authorization':`Bearer ${token}`, 'Content-Type':'application/json'}, body:JSON.stringify(body), credentials:'omit', cache:'no-store', signal:controller.signal});
    if (current !== epoch) return null;
    if (!response.ok) {
      const denied = response.status === 401 || response.status === 403;
      const message = body.action === 'proof-discover' && [422,429].includes(response.status) ? 'Discovery reached a work limit or its workers are busy. Retry the same batch; existing scan coverage is unchanged.' : ['content','proof-content','proof-attempt'].includes(body.action) && response.status === 422 ? 'Content interpretation reached a presentation limit or deadline. Inspect Source or select fewer complete captures; retained bytes remain available.' : ['content','proof-content','proof-attempt'].includes(body.action) && response.status === 429 ? 'Content workers are busy. Wait for current interpretation to finish, then retry.' : denied ? 'Access unavailable or revoked. Reconnect with an authorized reader.' : response.status === 404
        ? 'Retained source is unavailable for this request. Choose another occurrence or refresh the snapshot.'
        : 'This response could not be verified. Retry, refresh the snapshot, or choose another scope.';
      const error = new Error(message); error.accessDenied = denied; error.keepContentSelection = ['content','proof-content','proof-attempt'].includes(body.action) && [422,429].includes(response.status); error.readerMessage = message; throw error;
    }
    const value = await response.json(); if (current !== epoch) return null; return value;
    } catch (error) { if (current !== epoch) return null; throw error; }
  }
  function run(fn) { Promise.resolve().then(fn).catch(error => {
    if (error.name === 'AbortError') return;
    const message = error.readerMessage || 'Reader unavailable. Retry, refresh the snapshot, or choose another scope.';
    if (error.accessDenied || $('library').hidden) lock(message);
    else { clearContent(!error.keepContentSelection); clearInspector(); if (!pin) { $('capability-list').replaceChildren(); $('scope').replaceChildren(); $('catalog-status').textContent = 'Source check failed · coverage is unknown. Retry sources.'; $('catalog-status').className = ''; } notice(message, true); }
  }); }
  function tab(name) {
    $('content-panel').hidden = name !== 'content'; $('content-tab').setAttribute('aria-pressed', String(name === 'content'));
    $('source-panel').hidden = name !== 'source'; $('provenance').hidden = name !== 'provenance';
    $('source-tab').setAttribute('aria-pressed', String(name === 'source')); $('provenance-tab').setAttribute('aria-pressed', String(name === 'provenance'));
  }
  function renderBytes() {
    if (!source) return;
    const end = typeof source.offset === 'string' ? (BigInt(source.offset) + BigInt(source.bytes_hex.length / 2)).toString() : source.offset + source.bytes_hex.length / 2;
    $('range').textContent = `Bytes ${source.offset}–${end} of ${source.total_bytes} · ${hexadecimal ? 'hex' : 'UTF-8'} · end exclusive`;
    $('source').textContent = hexadecimal ? source.bytes_hex : source.utf8;
    $('encoding').textContent = hexadecimal ? 'Show UTF-8' : 'Show hex';
    $('encoding').disabled = source.utf8 === null;
  }
  function showSource(value) {
    const unavailable = value.availability === 'missing' || value.availability === 'corrupt';
    source = unavailable ? null : value; $('download').disabled = unavailable; $('source-tab').disabled = false; $('provenance-tab').disabled = false; $('inspection').hidden = false; $('close-inspector').hidden = false;
    $('selection').textContent = `Occurrence ${value.record.sequence}`;
    $('source-hint').textContent = value.content_trust;
    if (unavailable) {
      $('source').textContent = `Retained source is ${value.availability}. Issuer-attested metadata remains available.`;
      $('range').textContent = 'No source bytes available'; $('encoding').disabled = true; $('more').disabled = true;
    } else {
    hexadecimal = value.utf8 === null || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/.test(value.utf8);
    renderBytes(); $('more').disabled = value.next === null;
    }
    $('provenance').replaceChildren();
    for (const [key, val] of Object.entries({Scope:value.scope, Manifest:value.record.manifest, Receipt:value.record.receipt, 'Observed writer':value.writer || 'Unavailable for present-time verification', Observer:'Not normalized in this source view', 'Claimed speaker':'Not inferred from the writer key', 'Service issuer':value.service_issuer, Signature:value.signature, Admission:value.admission, 'Content trust':value.content_trust, ...(value.archive ? {Archive:value.archive, Profile:value.profile, 'Proof purpose':value.record.purpose, 'Attested at (Unix milliseconds)':value.record.issued_at, 'Receipt issuer':value.record.receipt_issuer, Attestation:value.record.attestation, Availability:value.availability} : {})})) {
      const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = key; dd.textContent = val; $('provenance').append(dt); $('provenance').append(dd);
    }
    notice(unavailable ? `Source ${value.availability} · provenance retained; no bytes substituted.` : 'Source verified · this is one retained occurrence, not a reconstructed session.');
  }
  async function inspect(sequence, offset = 0) {
    updateSelection(); clearInspector(); selected = sequence; const button = buttons.get(sequence); if (button) button.setAttribute('aria-pressed','true');
    notice('Verifying snapshot membership and reading source…');
    const value = await rpc(sourceRequest(sequence, offset)); if (!value) return;
    showSource(value); tab('source'); $('source-tab').focus();
  }
  async function page(position) {
    clearContent(); checks.clear(); clearInspector(); buttons.clear(); selections.clear(); $('rows').replaceChildren();
    $('count').textContent = ''; $('coverage').textContent = ''; $('page-position').textContent = 'Loading…';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    notice('Reading the selected snapshot…');
    const value = await rpc(isProof() ? {action:'proof-page',source:sourceId(activeSource),pin,cursor:position || null,limit:20} : pinWire ? {action:'content-page',pin_wire:pinWire,after:String(position),limit:20} : {action:'page', pin, after:position, limit:20}); if (!value) return;
    after = position; next = value.next; buttons.clear(); $('rows').replaceChildren();
    for (const row of value.records) {
      const button = document.createElement('button'); button.className = 'occurrence'; button.setAttribute('aria-pressed','false');
      const title = document.createElement('strong'), id = document.createElement('span'); title.textContent = `Occurrence ${row.sequence}`; id.textContent = row.manifest;
      button.append(title); button.append(id);
      if (isProof()) {
        if (!['available','missing','corrupt'].includes(row.availability) || !row.selection || typeof row.sequence !== 'string') throw new Error('Invalid proof occurrence.');
        selections.set(row.sequence, row.selection);
        const badge = document.createElement('span'); badge.className = `availability ${row.availability}`; badge.textContent = `${row.availability} · ${row.purpose}`; button.append(badge);
      } button.addEventListener('click', () => run(() => inspect(row.sequence))); buttons.set(row.sequence,button);
      if (contentEnabled && pinWire) {
        const wrap = document.createElement('div'), check = document.createElement('input'); wrap.className = 'selectable-occurrence';
        check.type = 'checkbox'; check.setAttribute('aria-label', `Select occurrence ${row.sequence} for Content`); checks.set(row.sequence,check);
        check.addEventListener('change', () => { cancelWork(); clearContent(false); attemptMode = false; clearInspector(); if(check.checked)contentSelection.add(String(row.sequence));else contentSelection.delete(String(row.sequence));updateSelection(); });
        wrap.append(check); wrap.append(button); $('rows').append(wrap);
      } else $('rows').append(button);
    }
    $('count').textContent = `${value.through} at snapshot`; $('coverage').textContent = value.coverage;
    $('page-position').textContent = value.records.length ? `${value.records[0].sequence}–${value.records[value.records.length-1].sequence}` : '0 entries';
    $('empty').hidden = value.records.length !== 0; $('previous').disabled = history.length === 0; $('next').disabled = next === null;
    notice('Snapshot pinned · refresh the snapshot to include newer entries.');
  }
  function renderCapabilities(value) {
    if (!Array.isArray(value.capabilities) || !Array.isArray(value.unavailable)) throw new Error('Unsupported capability response.');
    const labels = {'attempt-content':'Large attempt Content','session-links':'Explicit session relationships','attempt-discovery':'Captured attempt discovery','snapshot-inventory':'Snapshot inventory','source-ranges':'Source ranges','provenance':'Provenance','content-inspection':'Selected Content','payload-availability':'Payload availability','semantic-search':'Search','normalized-sessions':'Sessions','annotations':'Annotations','saved-views':'Saved views','analysis':'Analysis','administrative-jobs':'Admin jobs'};
    const supported = new Set(['snapshot-inventory','source-ranges','provenance','content-inspection','payload-availability','attempt-discovery','attempt-content','session-links']), seen = new Set();
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
  function validateScopes(value, version) {
    const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
    if (!Array.isArray(value) || value.length > 16) throw new Error('Invalid scope catalog.');
    const seen = new Set();
    for (const entry of value) {
      if (!object(entry) || typeof entry.scope !== 'string' || !entry.scope.length || entry.scope.length > 256 || seen.has(sourceId(entry))
          || !object(entry.pin) || typeof entry.pin.request !== 'string' || !entry.pin.request.length || entry.pin.request.length > 8192 || !object(entry.pin.reply)) {
        throw new Error('Invalid or duplicate scope entry.');
      }
      if (entry.pin_wire !== undefined && (typeof entry.pin_wire !== 'string' || !entry.pin_wire.length || entry.pin_wire.length > 12000)) throw new Error('Invalid exact snapshot.');
      if (version === 2 && (typeof entry.id !== 'string' || !entry.id.length || entry.id.length > 512 || !['legacy','kan-proof-reader/1'].includes(entry.protocol) || !Array.isArray(entry.capabilities))) throw new Error('Invalid source protocol.');
      seen.add(sourceId(entry));
    }
  }
  async function catalog() {
    clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren();
    pinWire = null; contentEnabled = false; activeSource = null; clearDiscovery(); selections.clear();
    scopes = []; pin = null; history = []; after = 0; next = null;
    $('coverage').textContent = ''; $('count').textContent = ''; $('page-position').textContent = '';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    $('capability-list').replaceChildren(); $('catalog-status').textContent = 'Checking configured sources…';
    notice('Checking scope access…');
    const value = await rpc({action:'catalog'}); if (!value) return;
    if (![1,2].includes(value.version) || !['complete','partial'].includes(value.coverage)) throw new Error('Unsupported reader version or coverage.');
    validateScopes(value.scopes, value.version);
    renderCapabilities(value);
    catalogContent = value.capabilities.includes('content-inspection');
    if (value.scopes.some(s => (s.capabilities?.includes('content-inspection') || (value.version === 1 && catalogContent)) && typeof s.pin_wire !== 'string')) throw new Error('Missing exact snapshot.');
    scopes = value.scopes;
    for (const scope of scopes) { const option = document.createElement('option'); option.value = sourceId(scope); option.textContent = scope.protocol === 'kan-proof-reader/1' ? `${scope.scope} · ${scope.binding.profile} · ${scope.binding.archive}` : scope.scope; $('scope').append(option); }
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
    $('scope').value = sourceId(scopes[0]); choose(scopes[0]); await page(0);
  }

  function choose(entry) {
    clearDiscovery(); activeSource = entry; pin = entry.pin; pinWire = entry.pin_wire || null; history = [];
    $('discovery').hidden = !entry.capabilities?.includes('attempt-discovery');
    contentEnabled = entry.capabilities ? entry.capabilities.includes('content-inspection') : catalogContent;
    $('content-support').textContent = contentEnabled ? 'Select captures on this page. Interpretation covers only this selection.' : 'Selected Content is not yet available for this source. Source and provenance remain browsable.';
  }
  function clearDiscovery() {
    discoveryRun++; discovered.clear(); scanCursor = null; scanComplete = false; scanCount = 0;
    $('attempts').replaceChildren(); $('sessions').replaceChildren(); $('discovery').hidden = true;
    $('discovery-coverage').textContent = 'No capture discovery has run for this snapshot.';
    $('scan-window').disabled = false; $('stop-scan').disabled = true;
    $('scan-attempts').disabled = false; $('scan-attempts').textContent = 'Discover attempts';
  }
  function renderDiscovery() {
    const groups = new Map(), other = [];
    for (const item of discovered.values()) {
      const d = item.description;
      if (d.kind !== 'capture') { other.push(item); continue; }
      const key = JSON.stringify([sourceId(activeSource), item.writer, d.observer, d.attempt]);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(item);
    }
    const root = $('attempts'); root.replaceChildren();
    renderSessions(groups);
    $('discovery-coverage').textContent = `${scanCount} occurrences inspected · ${discovered.size} in this window · ${groups.size} attempt groups · ${other.length} unassigned. ${scanComplete ? 'Inventory scan finished; traffic completeness remains unknown.' : 'Partial inventory coverage; continue scanning for older records.'}`;
    $('scan-attempts').disabled = scanComplete;
    $('scan-attempts').textContent = scanComplete ? 'Scan complete' : discovered.size >= 1000 ? 'Continue in a new window' : scanCount ? 'Scan next 20 occurrences' : 'Discover attempts';
    function sourceButton(parent, item) {
      const b = textNode('button', `Source ${item.record.sequence}`);
      b.addEventListener('click', () => run(() => inspect(item.record.sequence))); parent.append(b);
    }
    for (const items of groups.values()) {
      items.sort((a,b) => BigInt(a.description.ordinal) < BigInt(b.description.ordinal) ? -1 : BigInt(a.description.ordinal) > BigInt(b.description.ordinal) ? 1 : 0);
      const d = items[0].description, card = document.createElement('details'); card.className = 'attempt';
      const start = items.find(x => x.description.event.type === 'started');
      card.append(textNode('summary', `${start ? start.description.event.method + ' ' + start.description.event.route : 'Start not observed'} · ${d.observer} · ${items.length} records`));
      card.append(textNode('p', `Attempt ${d.attempt} · Writer ${items[0].writer}`, 'content-identity'));
      card.append(textNode('p', 'Records from the scanned window only. Read Content for stream gaps, conflicting ordinals and outcome claims.', 'content-coverage'));
      const step = activeSource.capabilities?.includes('attempt-content') ? 1024 : 40;
      if (contentEnabled && pinWire) for (let i=0; i<items.length; i+=step) {
        const chunk = items.slice(i,i+step), b = textNode('button', step === 1024 ? `Read attempt · ${chunk.length} observed records` : `Read records ${i+1}–${i+chunk.length}`);
        b.addEventListener('click', () => readDiscoveredAttempt(chunk)); card.append(b);
      }
      const lineage = document.createElement('details'); lineage.append(textNode('summary','Observed events and source'));
      for (const item of items) { const row = textNode('p', `Ordinal ${item.description.ordinal} · ${item.description.event.type} `); sourceButton(row,item); lineage.append(row); }
      card.append(lineage); root.append(card);
    }
    if (other.length) {
      const list = document.createElement('details'); list.append(textNode('summary', `${other.length} unassigned occurrences · missing, corrupt or unrecognized`));
      for (const item of other) { const row = textNode('p', `${item.description.kind} `); sourceButton(row,item); list.append(row); }
      root.append(list);
    }
  }
  async function discoverWindow(all = false) {
    if (!pin || !isProof() || scanComplete) return;
    const currentRun = ++discoveryRun; let batches=0;
    $('scan-window').disabled = true; $('stop-scan').disabled = false;
    // Explicit user-triggered work, at most one thousand descriptions per window.
    clearContent(); clearInspector(); $('scan-attempts').disabled = true;
    notice('Verifying captured records for attempt discovery…');
    try { do {
      const value = await rpc({action:'proof-discover',source:sourceId(activeSource),pin,cursor:scanCursor,limit:20});
      if (!value) return;
      if (value.version !== 'kan-discovery/1' || !Array.isArray(value.records) || value.records.length > 20) throw new Error('Invalid discovery response.');
      for (const item of value.records) {
        if (!item?.record?.selection || typeof item.record.sequence !== 'string' || !item.description || !['capture','opaque','unsupported','malformed','missing','corrupt'].includes(item.description.kind)) throw new Error('Invalid discovery record.');
        if (item.description.kind === 'capture' && (typeof item.writer !== 'string' || !/^(0|[1-9][0-9]*)$/.test(item.description.ordinal) || typeof item.description.attempt !== 'string' || !item.description.event)) throw new Error('Invalid capture identity.');
      }
      if (discovered.size + value.records.length > 1000) discovered.clear();
      for (const item of value.records) discovered.set(item.record.sequence,item);
      scanCount += value.records.length; scanCursor = value.next; scanComplete = value.next === null;
      renderDiscovery(); batches++; notice('Attempt discovery updated · coverage and unassigned evidence are shown.');
      $('scan-attempts').disabled = true;
    } while (all && currentRun === discoveryRun && !scanComplete && discovered.size < 1000 && batches < 50);
    } finally { if (currentRun === discoveryRun) { $('scan-attempts').disabled = scanComplete; $('scan-window').disabled = scanComplete; $('stop-scan').disabled = true; } }
  }
  $('scan-attempts').addEventListener('click', () => run(() => discoverWindow()));
  $('scan-window').addEventListener('click', () => run(() => discoverWindow(true)));
  $('stop-scan').addEventListener('click', () => { discoveryRun++; cancelWork(); $('scan-attempts').disabled=scanComplete; $('scan-window').disabled=scanComplete; $('stop-scan').disabled=true; notice('Scan stopped. Completed batches remain visible with their coverage.'); });
  function readDiscoveredAttempt(items) {
    cancelWork();clearContent();clearInspector();attemptMode=activeSource.capabilities?.includes('attempt-content')===true;
    if (!attemptMode && items.length>40) {notice('This reader supports only 40-record selections. Open the attempt below.',true);return;}
    for (const item of items) contentSelection.add(item.record.sequence);updateSelection();$('interpret').click();
  }
  function renderSessions(groups) {
    const root = $('sessions'); root.replaceChildren();
    const sessions = new Map();
    for (const [key,items] of groups) for (const item of items) {
      const link = item.description.session_link; if (!link) continue;
      if (link.state !== 'claimed') {
        root.append(textNode('p',`Occurrence ${item.record.sequence}: explicit session headers could not be interpreted. Inspect Source for the original claim.`, 'content-warning'));
        continue;
      }
      const id = JSON.stringify([sourceId(activeSource),item.writer,item.description.observer,link.scheme,link.session]);
      if (!sessions.has(id)) sessions.set(id,{session:link.session,scheme:link.scheme,claims:[]});
      sessions.get(id).claims.push({key,item,link});
    }
    if (!sessions.size) { root.append(textNode('p','No valid explicit session links in this scanned window. Attempts remain independent.','content-coverage')); return; }
    root.append(textNode('h3','Explicit session relationships'));
    root.append(textNode('p','Observer-recorded claims within this archive and scanned window. Parent links, branches and compaction do not merge or replace source history.','content-coverage'));
    for (const session of sessions.values()) {
      const card=document.createElement('details'); card.className='attempt'; card.append(textNode('summary',`Session ${session.session} · ${session.scheme} · ${session.claims.length} link claims`));
      for (const {key,item,link} of session.claims) {
        const row=textNode('p',`${link.transition} · ${item.description.attempt} ← ${link.parent_attempt || (link.transition === 'membership' ? 'no parent claim' : 'start')} `,'content-identity');
        const read=textNode('button','Read linked attempt');
        read.addEventListener('click',()=>readDiscoveredAttempt(groups.get(key)));row.append(read);
        const citation=textNode('button',`Session link source ${item.record.sequence}`);citation.addEventListener('click',()=>run(()=>inspect(item.record.sequence)));row.append(citation);
        if (link.parent_attempt) {
          const parentKey=JSON.stringify([sourceId(activeSource),item.writer,item.description.observer,link.parent_attempt]);
          const parents=groups.get(parentKey);
          if(parents){const parent=textNode('button','Read parent attempt');parent.addEventListener('click',()=>readDiscoveredAttempt(parents));row.append(parent);}
          row.append(textNode('span',parents?' Parent observed in this window; relationship remains a claim.':' Parent not observed in this window.'));
          if (link.parent_attempt===item.description.attempt) row.append(textNode('span',' Self-reference; no causal ordering inferred.'));
        }
        const claims=groups.get(key).map(x=>x.description.session_link).filter(x=>x?.state==='claimed');
        if(new Set(claims.map(x=>JSON.stringify([x.scheme,x.session,x.parent_attempt,x.transition]))).size>1)row.append(textNode('span',' Conflicting session claims retained.'));
        card.append(row);
      }
      root.append(card);
    }
  }
  function appendPagedText(parent, text, className) {
    const pageSize=32768, offsets=[0];
    for(let end=pageSize;end<text.length;end+=pageSize){if(/[\uD800-\uDBFF]/.test(text[end-1])&&/[\uDC00-\uDFFF]/.test(text[end]))end--;offsets.push(end);}
    const pre=textNode('pre',text.slice(0,offsets[1]||text.length),className);parent.append(pre);
    if(offsets.length===1)return;
    const controls=document.createElement('div');controls.className='pagination';
    const previous=textNode('button','Previous text page'), position=textNode('span',''), next=textNode('button','Next text page');let page=0;
    function render(){pre.textContent=text.slice(offsets[page],offsets[page+1]||text.length);position.textContent=`Text page ${page+1} of ${offsets.length} · derived display`;previous.disabled=page===0;next.disabled=page+1===offsets.length;}
    previous.addEventListener('click',()=>{page=Math.max(0,page-1);render();});next.addEventListener('click',()=>{page=Math.min(offsets.length-1,page+1);render();});
    controls.append(previous);controls.append(position);controls.append(next);parent.append(controls);render();
  }
  function sourceRequest(sequence, offset = 0) {
    if (isProof()) {
      const selection = discovered.get(String(sequence))?.record.selection || selections.get(String(sequence)); if (!selection) throw new Error('Missing verified selection.');
      return {action:'proof-source',source:sourceId(activeSource),pin,selection,offset:String(offset),length:'65536'};
    }
    return pinWire ? {action:'source-exact',pin_wire:pinWire,sequence:String(sequence),offset:String(offset),length:'65536'} : {action:'source',pin,sequence,offset,length:65536};
  }
  function textNode(tag, text, className) { const e=document.createElement(tag);e.textContent=text;if(className)e.className=className;return e; }
  function sourceLink(parent, value, input, label, offset = '0') {
    const occurrence = value.occurrences[Number(input)]; if(!occurrence)throw new Error('Invalid Content citation.');
    const button=textNode('button',label);button.addEventListener('click',()=>run(async()=>{returnItem=button;await inspect(occurrence.record.sequence,offset);}));parent.append(button);return button;
  }
  function details(parent, title, raw) {
    const d=document.createElement('details');d.append(textNode('summary',title));appendPagedText(d,raw,'');parent.append(d);
  }
  function citationRenderer(value, stream) {
    if(!Array.isArray(stream.citation_sets)||stream.citation_sets.length>(attemptMode?32768:2048)||!Array.isArray(stream.items))throw new Error('Invalid Content citation table.');
    let total=0;
    for(const set of stream.citation_sets){
      if(!Array.isArray(set)||(total+=set.length)>(attemptMode?32768:4096))throw new Error('Invalid Content citation table.');
      for(const c of set)if(!c||!Array.isArray(c.bytes)||c.bytes.length!==2||!value.occurrences[Number(c.input)])throw new Error('Invalid Content citation.');
    }
    function resolve(ref){
      if(typeof ref!=='string'||ref.length>20||!/^(0|[1-9][0-9]*)$/.test(ref))throw new Error('Invalid Content citation reference.');
      const index=Number(ref);
      if(!Number.isSafeInteger(index)||index>=stream.citation_sets.length)throw new Error('Invalid Content citation reference.');
      return stream.citation_sets[index];
    }
    const uses=new Map(),shared=new Map();
    for(const item of stream.items)for(const ref of [item.citation_set,...(item.tool?[item.tool.citation_set]:[])]){resolve(ref);uses.set(ref,(uses.get(ref)||0)+1);}
    function links(parent, ref, label){let first;for(const c of resolve(ref)){const button=sourceLink(parent,value,c.input,`${label} ${value.occurrences[Number(c.input)].record.sequence} · ${c.bytes.join('–')}`,c.bytes[0]);first ||= button;}return first;}
    return {
      append(parent,ref,label){
        if(uses.get(ref)===1){links(parent,ref,label);return;}
        if(!shared.has(ref)){
          const detail=document.createElement('details');detail.className='content-citation-set';
          const summary=textNode('summary',`Shared source range ${Number(ref)+1} · ${resolve(ref).length} citations`);detail.append(summary);
          const sources=document.createElement('div');sources.className='content-citations';const target=links(sources,ref,'Source')||summary;detail.append(sources);shared.set(ref,{detail,target});
        }
        const button=textNode('button',`Sources · shared range ${Number(ref)+1}`);button.addEventListener('click',()=>{const group=shared.get(ref);group.detail.open=true;group.target.focus();});parent.append(button);
      },
      finish(parent){for(const group of shared.values())parent.append(group.detail);}
    };
  }
  function showContent(value) {
    if(value.version!=='kan-content/2'||value.pin_wire!==pinWire||!Array.isArray(value.occurrences)||value.occurrences.length>(attemptMode?1024:40)||!Array.isArray(value.observations)||!Array.isArray(value.groups))throw new Error('Unsupported Content response.');
    contentValue=value;$('content-panel').replaceChildren();$('content-tab').disabled=false;
    $('inspection').hidden=false;$('close-inspector').hidden=false;$('selection').textContent='Selected Content';
    $('source-hint').textContent='Observed content · roles and outcomes are claims. Follow citations to verified retained source.';
    const panel=$('content-panel');panel.append(textNode('p',value.coverage,'content-coverage'));
    const unplaced=value.observations.filter(o=>o.kind!=='capture');
    if(unplaced.length){const section=document.createElement('section');section.className='content-unplaced';section.append(textNode('h3','Other selected evidence'));for(const o of unplaced){const row=document.createElement('p');row.append(textNode('span',`${o.kind}${o.reason?' · '+o.reason:''} `));sourceLink(row,value,o.input,'Inspect source');section.append(row);}panel.append(section);}
    if(!value.groups.length)panel.append(textNode('p','No recognized capture groups in this selection. Every input remains inspectable in Source.'));
    for(const group of value.groups){
      const card=document.createElement('section');card.className='content-group';
      card.append(textNode('h3',`${group.observer} · ${group.terminal}`));card.append(textNode('p',group.attempt,'content-identity'));card.append(textNode('p',`Retained request signer: ${group.writer}`,'content-identity'));
      const flags=[];if(group.missing_start)flags.push('Start not selected');if(group.events_after_terminal)flags.push('Events after terminal');if(group.unconfirmed_claim)flags.push('Observer reports unconfirmed capture');
      if(group.ordinal_gaps.length)flags.push(`No recognized capture at ordinals ${group.ordinal_gaps.map(r=>r.join('–')).join(', ')} (end exclusive)`);
      if(group.ordinals.some(o=>o.conflict))flags.push('Conflicting ordinal · both streams withheld conservatively');
      if(flags.length)card.append(textNode('p',flags.join(' · '),'content-warning'));
      if(group.unexpected_starts.length){const row=textNode('p','Unexpected start events: ','content-warning');for(const input of group.unexpected_starts)sourceLink(row,value,input,`Unexpected start · Source ${value.occurrences[Number(input)].record.sequence}`);card.append(row);}
      const lineage=document.createElement('details');lineage.className='content-lineage';lineage.append(textNode('summary','Retained occurrence lineage'));
      for(const ordinal of group.ordinals){const row=document.createElement('p');row.append(textNode('span',`Observed ordinal ${ordinal.value}${ordinal.conflict?' · conflict':''} `));for(const input of ordinal.inputs)sourceLink(row,value,input,`Source ${value.occurrences[Number(input)].record.sequence}`);lineage.append(row);}card.append(lineage);
      for(const direction of ['request','response']){
        const stream=group[direction],citations=citationRenderer(value,stream),section=document.createElement('section');section.className='content-stream';section.append(textNode('h4',direction==='request'?'Request · supplied history':'Response · observed output'));
        section.append(textNode('p',`Contiguous selected bytes: ${stream.observed_bytes??'unavailable'} · Consistent observer length claim: ${stream.expected_bytes??'none'}`,'content-coverage'));
        if(stream.extent_claims.length){const claims=document.createElement('details');claims.append(textNode('summary','Observer length claims'));for(const claim of stream.extent_claims){const row=textNode('p',`Claimed bytes: ${claim.bytes} `);sourceLink(row,value,claim.input,`Length claim · Source ${value.occurrences[Number(claim.input)].record.sequence}`);claims.append(row);}section.append(claims);}
        if(stream.state!=='interpreted')section.append(textNode('p',`No readable stream: ${stream.issues.map(i=>i.kind+(i.bytes?' '+i.bytes.join('–'):'')).join(', ')||'absent, incomplete or contradictory selected bytes'}.`,'content-warning'));
        else {
          if(stream.coherent_stop_observed)section.append(textNode('p','Coherent protocol stop observed · capture completeness is unknown.','content-coverage'));
          for(const item of stream.items){const entry=document.createElement('article');entry.className='content-item';entry.append(textNode('h5',`${direction==='request'?'Supplied history · ':''}${item.role?item.role+' · ':''}${item.kind}${item.index!==null?' · block '+item.index:''}`));
            if(item.text!==null)appendPagedText(entry,item.text,'content-text');
            if(item.issues.length)entry.append(textNode('p',item.issues.join(' · '),'content-warning'));
            if(item.pointer!==null)entry.append(textNode('p',`Parsed JSON location ${item.pointer||'/'}`,'content-pointer'));
            if(item.event_json!==null)details(entry,'Parsed event · numbers may be rounded; Source preserves exact bytes',item.event_json);
            if(item.tool){details(entry,'Accumulated tool input (derived)',item.tool.json);const refs=document.createElement('div');refs.className='content-citations';refs.append(textNode('span',`Enclosing tool block ${item.tool.region.join('–')} · coarse attribution · end exclusive`));citations.append(refs,item.tool.citation_set,'Tool input source');entry.append(refs);}
            const sources=document.createElement('div');sources.className='content-citations';sources.append(textNode('span',`Enclosing bytes ${item.region.join('–')} · ${item.coarse?'coarse attribution':'attribution'} · end exclusive`));
            citations.append(sources,item.citation_set,'Source');
            entry.append(sources);section.append(entry);
          }
          citations.finish(section);
          if(stream.parsed_json!==null)details(section,'Parsed body · numbers may be rounded; Source preserves exact bytes',stream.parsed_json);
        }
        card.append(section);
      }
      panel.append(card);
    }
    tab('content');$('content-tab').focus();notice('Content interpreted from the explicit selection · original source and provenance remain available.');
  }
  $('interpret').addEventListener('click',()=>run(async()=>{
    if(!pinWire||!contentEnabled||!contentSelection.size)return;
    clearContent(false);clearInspector();$('interpret').disabled=true;notice('Verifying selected evidence and interpreting Content…');
    const value=await rpc(isProof() ? {action:attemptMode?'proof-attempt':'proof-content',source:sourceId(activeSource),pin,selections:[...contentSelection].map(n=>discovered.get(n)?.record.selection || selections.get(n)),format:$('content-format').value} : {action:'content',pin_wire:pinWire,sequences:[...contentSelection],format:$('content-format').value});if(!value)return;
    showContent(value);updateSelection();
  }));
  $('clear-content').addEventListener('click',()=>{cancelWork();clearContent();clearInspector();notice('Content selection cleared.');});
  $('content-format').addEventListener('change',()=>{cancelWork();clearContent(false);clearInspector();});

  $('connect').addEventListener('submit', event => {
    event.preventDefault(); token = $('token').value; $('token').value = ''; run(catalog);
  });
  $('retry-sources').addEventListener('click', () => run(catalog));
  $('scope').addEventListener('change', () => run(async () => { const chosen = scopes.find(s => sourceId(s) === $('scope').value); if (!chosen) return; choose(chosen); await page(0); }));
  $('resnapshot').addEventListener('click', () => run(async () => { if (!pin) return; clearDiscovery(); clearContent(); clearInspector(); const value = await rpc(isProof() ? {action:'proof-snapshot',source:sourceId(activeSource)} : {action:'snapshot',scope:$('scope').value}); if (!value) return; if(contentEnabled && typeof value.pin_wire !== 'string') throw new Error('Missing exact snapshot.'); pin = value.pin; pinWire = value.pin_wire || null; $('discovery').hidden = !activeSource?.capabilities?.includes('attempt-discovery'); const chosen = scopes.find(s => sourceId(s) === $('scope').value); chosen.pin = pin; chosen.pin_wire = pinWire; history = []; await page(0); }));
  $('next').addEventListener('click', () => run(async () => { if (next === null) return; history.push(after); await page(next); }));
  $('previous').addEventListener('click', () => run(async () => { if (history.length) await page(history.pop()); }));
  $('more').addEventListener('click', () => run(async () => { if (source && source.next !== null) await inspect(selected,source.next); }));
  $('download').addEventListener('click', () => run(async () => {
    if (!source) return; const offset = source.offset, sequence = selected;
    // Export rechecks authorization; the displayed range is not an offline grant.
    const request = sourceRequest(sequence,offset); clearInspector(); selected = sequence;
    const value = await rpc(request); if (!value) return;
    showSource(value); if (value.availability === 'missing' || value.availability === 'corrupt') return;
    const bytes = new Uint8Array(value.bytes_hex.match(/../g)?.map(x => parseInt(x,16)) || []);
    const url = URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));
    // Keep the URL alive for navigation to begin; lock/pagehide release it early.
    exports.set(url, setTimeout(() => releaseExport(url), 1000));
    const a = document.createElement('a'); a.href = url; a.download = `kan-occurrence-${sequence}-offset-${offset}.bin`;
    a.hidden = true; document.body.append(a); a.click(); a.remove();
  }));
  $('encoding').addEventListener('click', () => { if (source && source.utf8 !== null) { hexadecimal = !hexadecimal; renderBytes(); } });
  $('content-tab').addEventListener('click', () => { if(contentValue) { tab('content'); $('selection').textContent = 'Selected Content'; $('source-hint').textContent = 'Observed content · roles and outcomes are claims. Follow citations to verified retained source.'; if(returnItem)returnItem.focus(); } });
  $('source-tab').addEventListener('click', () => tab('source')); $('provenance-tab').addEventListener('click', () => tab('provenance'));
  $('close-inspector').addEventListener('click', () => { epoch++; if(controller) controller.abort(); const button = buttons.get(selected); clearContent(false); clearInspector(); if(button)button.focus(); });
  $('lock').addEventListener('click', () => lock());
  window.addEventListener('pagehide', () => lock());
})();
