(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let ownerToken='',ownerEpoch=0,ownerController,ownerTargets=[],ownerPreview=null,ownerRetry=null;
  let token = '', epoch = 0, controller, scopes = [], pin, after = 0, next = null, history = [], selected = null, source = null, hexadecimal = false;
  const selections = new Map();
  let activeSource = null, catalogContent = false;
  const discovered = new Map();
  let workspaceStates = [], workspaceRun = 0;
  let scanCursor = null, scanComplete = false, scanCount = 0, discoveryRun = 0;
  const sourceId = entry => entry.id || entry.scope;
  const isProof = () => activeSource?.protocol === 'kan-proof-reader/1';
  const buttons = new Map(), exports = new Map(), contentSelection = new Set(), checks = new Map();
  let searchStates = [], searchRun = 0, searchFilter = null, searchHits = new Map(), searchPages = 0;
  let analysisEnabled=false,analysisDraft=null,analysisPreview=null,analysisRecipes=[];
  let annotationsEnabled=false, annotationCites=[], annotationDerivations=[], annotationRelations=[], annotationSupersedes=null, annotationPreview=null;
  let attemptMode = false;
  let pinWire = null, contentEnabled = false, contentValue = null, returnItem = null;
  function navigation(visible) {
    for(const [id,section] of [['evidence','evidence'],['search','search-workspace'],['sessions','session-workspace'],['imports','discovery'],['knowledge','knowledge'],['views','search-workspace'],['analysis','analysis'],['owner','owner-maintenance']])$('nav-'+id).hidden=!visible||$(section).hidden;
  }
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
    $('annotate-source').hidden=true;$('analyze-source').hidden=true;
    source = null; selected = null; $('download').disabled = true; $('more').disabled = true; $('source-tab').disabled = true; $('provenance-tab').disabled = true; $('inspection').hidden = true; $('source').textContent = '';
    $('provenance').replaceChildren(); $('range').textContent = ''; $('selection').textContent = 'Select an occurrence';
    $('source-hint').textContent = 'Read exact retained bytes alongside their provenance.'; $('close-inspector').hidden = true;
    for (const button of buttons.values()) button.setAttribute('aria-pressed', 'false');
  }
  function lock(message = 'Locked · connect to browse authorized evidence.') {
    for (const url of exports.keys()) releaseExport(url);
    epoch++; if (controller) controller.abort(); controller = null; token = ''; scopes = []; pin = null; history = []; after = 0; next = null;
    navigation(false);lockOwner();$('operations-link').hidden=true;clearAnalysis(true);clearKnowledge(true);clearSearch(true);
    pinWire = null; contentEnabled = false; activeSource = null; clearDiscovery(); clearWorkspace(); selections.clear(); clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren(); $('capability-list').replaceChildren(); $('coverage').textContent = '';
    $('catalog-status').textContent = ''; $('count').textContent = ''; $('page-position').textContent = ''; $('library').hidden = true; $('login').hidden = false;
    $('lock').disabled = true; $('token').value = ''; notice(message); $('token').focus();
  }
  async function rpc(body) {
    const current = ++epoch; if (controller) controller.abort(); controller = new AbortController();
    try {
    const response = await fetch(['proof-content','proof-attempt','proof-session','proof-import'].includes(body.action) ? `/api/library/${body.action}` : '/api/library', {method:'POST', headers:{'Authorization':`Bearer ${token}`, 'Content-Type':'application/json'}, body:JSON.stringify(body), credentials:'omit', cache:'no-store', signal:controller.signal});
    if (current !== epoch) return null;
    if (!response.ok) {
      const denied = response.status === 401 || response.status === 403;
      const message = body.action === 'proof-discover' && [422,429].includes(response.status) ? 'Discovery reached a work limit or its workers are busy. Retry the same batch; existing scan coverage is unchanged.' : ['content','proof-content','proof-attempt','proof-session','proof-import'].includes(body.action) && response.status === 422 ? 'Content interpretation reached a presentation limit or deadline. Inspect Source or select fewer complete captures; retained bytes remain available.' : ['content','proof-content','proof-attempt','proof-session','proof-import'].includes(body.action) && response.status === 429 ? 'Content workers are busy. Wait for current interpretation to finish, then retry.' : denied ? 'Access unavailable or revoked. Reconnect with an authorized reader.' : response.status === 404
        ? 'Retained source is unavailable for this request. Choose another occurrence or refresh the snapshot.'
        : 'This response could not be verified. Retry, refresh the snapshot, or choose another scope.';
      const error = new Error(message); error.accessDenied = denied; error.keepContentSelection = ['content','proof-content','proof-attempt','proof-session','proof-import'].includes(body.action) && [422,429].includes(response.status); error.readerMessage = message; throw error;
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
    $('annotate-source').hidden=!annotationsEnabled || !isProof();$('analyze-source').hidden=!analysisEnabled || !isProof() || value.availability==='missing' || value.availability==='corrupt';
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
    const labels = {'import-content':'Imported v1 files and claims','owner-maintenance':'Owner maintenance','operations-read':'Operations reader','text-search':'Persistent text search','attempt-content':'Large attempt Content','session-content':'Conversation reader','session-links':'Explicit session relationships','attempt-discovery':'Captured attempt discovery','snapshot-inventory':'Snapshot inventory','source-ranges':'Source ranges','provenance':'Provenance','content-inspection':'Selected Content','payload-availability':'Payload availability','semantic-search':'Search','normalized-sessions':'Sessions','annotations':'Annotations','saved-views':'Saved views','analysis':'Analysis','administrative-jobs':'Admin jobs'};
    const supported = new Set(['import-content','owner-maintenance','analysis','operations-read','text-search','saved-views','annotations','snapshot-inventory','source-ranges','provenance','content-inspection','payload-availability','attempt-discovery','attempt-content','session-links','session-content']), seen = new Set();
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
    navigation(false);lockOwner();$('operations-link').hidden=true;clearAnalysis(true);clearKnowledge(true);clearSearch(true);
    clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren();
    pinWire = null; contentEnabled = false; activeSource = null; clearDiscovery(); clearWorkspace(); selections.clear();
    scopes = []; pin = null; history = []; after = 0; next = null;
    $('coverage').textContent = ''; $('count').textContent = ''; $('page-position').textContent = '';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    $('capability-list').replaceChildren(); $('catalog-status').textContent = 'Checking configured sources…';
    notice('Checking scope access…');
    const value = await rpc({action:'catalog'}); if (!value) return;
    if (![1,2].includes(value.version) || !['complete','partial'].includes(value.coverage)) throw new Error('Unsupported reader version or coverage.');
    validateScopes(value.scopes, value.version);
    renderCapabilities(value);
    $('search-workspace').hidden = !value.capabilities.includes('text-search');
    $('operations-link').hidden=!value.capabilities.includes('operations-read');
    $('owner-maintenance').hidden=!value.capabilities.includes('owner-maintenance');
    clearAnalysis(true);analysisEnabled=value.capabilities.includes('analysis');$('analysis').hidden=!analysisEnabled;
    annotationsEnabled=value.capabilities.includes('annotations');$('knowledge').hidden=!annotationsEnabled;
    catalogContent = value.capabilities.includes('content-inspection');
    if (value.scopes.some(s => (s.capabilities?.includes('content-inspection') || (value.version === 1 && catalogContent)) && typeof s.pin_wire !== 'string')) throw new Error('Missing exact snapshot.');
    scopes = value.scopes;
    workspaceStates = scopes.filter(s => s.protocol === 'kan-proof-reader/1' && s.capabilities.includes('attempt-discovery')).map(entry => ({entry, cursor:null, complete:false, records:[], inspected:0, error:false}));
    $('session-workspace').hidden = workspaceStates.length === 0;
    renderWorkspace();
    for (const scope of scopes) { const option = document.createElement('option'); option.value = sourceId(scope); option.textContent = scope.protocol === 'kan-proof-reader/1' ? `${scope.scope} · ${scope.binding.profile} · ${scope.binding.archive}` : scope.scope; $('scope').append(option); }
    $('login').hidden = true; $('library').hidden = false; $('lock').disabled = false;
    navigation(true);
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
    $('discovery').hidden = !entry.capabilities?.includes('attempt-discovery');navigation(true);
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
  const fragmented = items => items.some(x=>x.description.event?.type==='http-metadata-chunk' && x.description.event.direction==='request');
  function effectiveItems(items) {
    return items.flatMap(item=>[item,...(item.resolved_metadata||[]).filter(m=>m.session_link).map(m=>({...item,description:{...item.description,session_link:m.session_link},link_sources:m.sources}))]);
  }
  async function resolveMetadata(entry,items,render) {
    clearContent();clearInspector();notice('Verifying metadata fragments and their source coordinates…');
    const value=await rpc({action:'proof-attempt',source:sourceId(entry),pin:entry.pin,selections:items.map(x=>x.record.selection),format:'anthropic-messages-json'});
    if(!value)return;
    if(value.version!=='kan-content/2'||value.pin_wire!==entry.pin_wire||!Array.isArray(value.groups)||!Array.isArray(value.occurrences)||value.occurrences.length!==items.length||value.occurrences.some((x,i)=>x.record.sequence!==items[i].record.sequence))throw new Error('Invalid metadata result.');
    const resolved=[];
    for(const group of value.groups)for(const m of group.metadata||[]) {
      if(!m.fragmented)continue;
      if(!['complete','incomplete','invalid','limited'].includes(m.state)||!Array.isArray(m.sources)||!m.sources.length||m.sources.length>items.length)throw new Error('Invalid metadata sources.');
      const sources=m.sources.map(c=>{
        if(typeof c.input!=='string'||!/^(0|[1-9][0-9]*)$/.test(c.input)||!items[Number(c.input)]||!Array.isArray(c.bytes)||c.bytes.length!==2||c.bytes.some(b=>typeof b!=='string'||!/^(0|[1-9][0-9]*)$/.test(b)))throw new Error('Invalid metadata coordinates.');
        return {sequence:items[Number(c.input)].record.sequence,offset:c.bytes[0]};
      });
      if(m.state!=='complete'&&m.session_link!==null)throw new Error('Incomplete metadata cannot supply a link.');
      resolved.push({anchor:Number(m.sources[0].input),state:m.state,session_link:m.session_link,sources});
    }
    for(const item of items){item.resolved_metadata=[];item.resolution_status=null;}
    for(const m of resolved)items[m.anchor].resolved_metadata.push(m);
    items[0].resolution_status=resolved.length?resolved.map(m=>`Metadata ${m.state}`).join(' · '):'No reconstructable request metadata in the currently available selection.';
    render();notice('Metadata resolution updated. Incomplete or conflicting documents do not produce session links.');
  }
  function metadataControl(parent,entry,items,render) {
    if(!fragmented(items))return;
    if(entry.capabilities?.includes('attempt-content')) {
      const b=textNode('button','Resolve chunked session links');b.addEventListener('click',()=>run(()=>resolveMetadata(entry,items,render)));parent.append(b);
    }
    for(const item of items)if(item.resolution_status)parent.append(textNode('p',item.resolution_status,'content-coverage'));
  }
  function renderDiscovery() {
    const groups = new Map(), imports = new Map(), other = [];
    for (const item of discovered.values()) {
      const d = item.description;
      if (d.kind === 'import') { const key=JSON.stringify([item.writer,d.plan]); if(!imports.has(key))imports.set(key,[]);imports.get(key).push(item);continue; }
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
      metadataControl(card,activeSource,items,renderDiscovery);
      const lineage = document.createElement('details'); lineage.append(textNode('summary','Observed events and source'));
      for (const item of items) { const row = textNode('p', `Ordinal ${item.description.ordinal} · ${item.description.event.type} `); sourceButton(row,item); lineage.append(row); }
      card.append(lineage); root.append(card);
    }
    for(const items of imports.values()) {
      const card=document.createElement('details');card.className='attempt';
      card.append(textNode('summary',`Imported v1 snapshot · ${items.length} frames`));
      card.append(textNode('p',`Plan ${items[0].description.plan} · Writer ${items[0].writer}`,'content-identity'));
      card.append(textNode('p','Scan enough inventory and file parts to reconstruct the selected file. Missing parts remain visible.','content-coverage'));
      const read=textNode('button','Browse imported files and claims');read.addEventListener('click',()=>run(()=>readImport(activeSource,items)));card.append(read);
      for(const item of items){const row=textNode('p',`${item.description.frame_kind} · ordinal ${item.description.ordinal} `);sourceButton(row,item);card.append(row);}root.append(card);
    }
    if (other.length) {
      const list = document.createElement('details'); list.append(textNode('summary', `${other.length} unassigned occurrences · missing, corrupt or unrecognized`));
      for (const item of other) { const row = textNode('p', `${item.description.kind} `); sourceButton(row,item); list.append(row); }
      root.append(list);
    }
  }
  async function readImport(entry,items,file=null,after=0) {
    clearContent();clearInspector();notice('Verifying imported file commitments and retained claim records…');
    const request={action:'proof-import',source:sourceId(entry),pin:entry.pin,selections:items.map(i=>i.record.selection),plan:items[0].description.plan,file,after};
    const value=await rpc(request);if(!value)return;
    if(value.version!=='kan-import-content/1'||value.source!==request.source||JSON.stringify(value.pin)!==JSON.stringify(entry.pin)||value.plan!==request.plan||!['inventory-verified','inventory-incomplete'].includes(value.state)||!Array.isArray(value.files)||value.files.length>16384||!Array.isArray(value.unavailable))throw new Error('Invalid import result.');
    const panel=document.createElement('div'), importSelections=new Map(items.map(i=>[i.record.sequence,i]));
    function sources(parent,cites) {
      if(!Array.isArray(cites)||cites.length>1024)throw new Error('Invalid import citations.');
      for(const c of cites) {
        const original=importSelections.get(c.record?.sequence);
        if(!original||!Array.isArray(c.bytes)||c.bytes.length!==2||c.bytes.some(x=>typeof x!=='string'||!/^(0|[1-9][0-9]*)$/.test(x))||BigInt(c.bytes[0])>BigInt(c.bytes[1]))throw new Error('Invalid import source.');
        const button=textNode('button',`Source ${c.record.sequence} · ${c.bytes.join('–')}`);button.addEventListener('click',()=>run(async()=>{
          clearInspector();selected=original.record.sequence;selections.set(selected,original.record.selection);const result=await rpc({action:'proof-source',source:sourceId(entry),pin:entry.pin,selection:original.record.selection,offset:c.bytes[0],length:'65536'});if(!result)return;showSource(result);tab('source');
        }));parent.append(button);
      }
    }
    panel.append(textNode('h2','Imported v1 snapshot'));panel.append(textNode('p',value.coverage,'content-coverage'));
    panel.append(textNode('p',`${value.state} · ${value.unavailable.length} unavailable selected records`,'content-identity'));
    if(value.state==='inventory-incomplete')panel.append(textNode('p','The complete inventory is not selected. Continue discovery to include its parts; file names and contents cannot yet be verified.','content-warning'));
    sources(panel,value.inventory_cites||[]);
    for(const f of value.files) {
      if(!Number.isSafeInteger(f.index)||typeof f.path!=='string'||typeof f.length!=='string')throw new Error('Invalid import file.');
      const row=document.createElement('article');row.append(textNode('h3',f.path));row.append(textNode('p',`${f.length} bytes · ${f.present_parts}/${f.parts} parts selected`));
      const open=textNode('button',`Read ${f.path}`);open.addEventListener('click',()=>run(()=>readImport(entry,items,f.index)));row.append(open);panel.append(row);
    }
    if(value.file) {
      const f=value.file;if(!['verified','incomplete'].includes(f.state)||f.index!==file)throw new Error('Invalid file result.');
      panel.append(textNode('h2',`${f.path} · ${f.state}`));
      if(f.state==='incomplete')panel.append(textNode('p','Select the remaining file parts to verify and read this file.','content-warning'));
      else {
        sources(panel,f.sources);
        if(f.car) {
          if(!Array.isArray(f.car.records)||f.car.records.length>100)throw new Error('Invalid CAR page.');
          panel.append(textNode('p',f.car.membership,'content-coverage'));
          if(f.car.scan.error)panel.append(textNode('p',`CAR inspection incomplete: ${f.car.scan.error}`,'content-warning'));
          for(const record of f.car.records) {
            const article=document.createElement('article');article.className='conversation-attempt';
            article.append(textNode('h3',`${record.state} · ${record.id||record.block}`));
            article.append(textNode('pre',JSON.stringify(record.claim||{notice:record.notice,codec:record.codec},null,2)));
            sources(article,record.sources);panel.append(article);
            if(annotationsEnabled&&record.state==='verified-claim'&&record.sources.length<=8){const note=textNode('button','Annotate this imported claim');note.addEventListener('click',()=>editAnnotation(record.sources.map(c=>({source:sourceId(entry),pin:entry.pin,selection:importSelections.get(c.record.sequence).record.selection})),`claim/${record.id}`));article.append(note);}
          }
          if(f.car.next!==null){if(!Number.isSafeInteger(f.car.next)||f.car.next<=after)throw new Error('Invalid CAR continuation.');const more=textNode('button','Next imported blocks');more.addEventListener('click',()=>run(()=>readImport(entry,items,file,f.car.next)));panel.append(more);}
        } else panel.append(textNode('pre',f.preview===null?'Binary bytes · inspect exact Source.':`${f.preview}${f.truncated?'\n[Preview truncated; exact bytes remain in Source.]':''}`));
      }
    }
    contentValue=value;$('content-panel').replaceChildren();$('content-panel').append(panel);$('content-tab').disabled=false;$('inspection').hidden=false;$('close-inspector').hidden=false;$('selection').textContent='Imported v1 evidence';tab('content');notice('Imported evidence ready · verification scope and exact sources are shown.');
  }
  function validateDiscovery(value) {
      if (value.version !== 'kan-discovery/1' || !Array.isArray(value.records) || value.records.length > 20) throw new Error('Invalid discovery response.');
      for (const item of value.records) {
        if (!item?.record?.selection || typeof item.record.sequence !== 'string' || !item.description || !['capture','import','opaque','unsupported','malformed','missing','corrupt'].includes(item.description.kind)) throw new Error('Invalid discovery record.');
        if (item.description.kind === 'import' && (typeof item.writer!=='string' || !/^[a-f0-9]{64}$/.test(item.description.plan) || !/^(0|[1-9][0-9]*)$/.test(item.description.ordinal))) throw new Error('Invalid import identity.');
        if (item.description.kind === 'capture' && (typeof item.writer !== 'string' || !/^(0|[1-9][0-9]*)$/.test(item.description.ordinal) || typeof item.description.attempt !== 'string' || !item.description.event)) throw new Error('Invalid capture identity.');
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
      validateDiscovery(value);
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
    for (const [key,items] of groups) for (const item of effectiveItems(items)) {
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
        for(const c of item.link_sources||[{sequence:item.record.sequence,offset:'0'}]){
          const citation=textNode('button',`Session link source ${c.sequence}`);citation.addEventListener('click',()=>run(()=>inspect(c.sequence,c.offset)));row.append(citation);
        }
        if (link.parent_attempt) {
          const parentKey=JSON.stringify([sourceId(activeSource),item.writer,item.description.observer,link.parent_attempt]);
          const parents=groups.get(parentKey);
          if(parents){const parent=textNode('button','Read parent attempt');parent.addEventListener('click',()=>readDiscoveredAttempt(parents));row.append(parent);}
          row.append(textNode('span',parents?' Parent observed in this window; relationship remains a claim.':' Parent not observed in this window.'));
          if (link.parent_attempt===item.description.attempt) row.append(textNode('span',' Self-reference; no causal ordering inferred.'));
        }
        const claims=effectiveItems(groups.get(key)).map(x=>x.description.session_link).filter(x=>x?.state==='claimed');
        if(new Set(claims.map(x=>JSON.stringify([x.scheme,x.session,x.parent_attempt,x.transition]))).size>1)row.append(textNode('span',' Conflicting session claims retained.'));
        card.append(row);
      }
      root.append(card);
    }
  }
  function clearWorkspace() {
    clearSessionReader();
    workspaceRun++; workspaceStates = [];
    $('workspace-sessions').replaceChildren(); $('workspace-sources').replaceChildren();
    $('workspace-coverage').textContent = ''; $('session-workspace').hidden = true;
    $('scan-archives').disabled = false; $('stop-archives').disabled = true;
  }
  function resetWorkspace() {
    clearSessionReader();
    workspaceRun++;
    for(const state of workspaceStates){state.records=[];state.cursor=null;state.complete=false;state.inspected=0;state.error=false;}
    renderWorkspace();$('stop-archives').disabled=true;
  }
  const attemptKey = item => JSON.stringify([item.writer,item.description.observer,item.description.attempt]);
  function workspaceGroups() {
    const groups=[];
    for (const state of workspaceStates) {
      const local=new Map();
      for(const item of state.records) if(item.description.kind==='capture') {
        const key=attemptKey(item);
        if(!local.has(key))local.set(key,{state,items:[],key});
        local.get(key).items.push(item);
      }
      groups.push(...local.values());
    }
    return groups;
  }
  function openWorkspace(group, sourceItem=null, offset='0') {
    cancelWork(); workspaceRun++; $('stop-archives').disabled=true;
    $('scan-archives').disabled=workspaceStates.every(s=>s.complete);
    const entry=group.state.entry;
    choose(entry); $('scope').value=sourceId(entry);
    clearContent(); checks.clear(); clearInspector(); buttons.clear(); selections.clear(); $('rows').replaceChildren();
    after=0;next=null;history=[];$('previous').disabled=true;$('next').disabled=true;
    $('count').textContent='Session selection';$('page-position').textContent='Choose an archive to browse its inventory';$('empty').hidden=true;$('coverage').textContent='Selected observed attempt; partial inventory coverage.';
    for(const item of group.items)discovered.set(item.record.sequence,item);
    scanCount=group.items.length;renderDiscovery();
    if(sourceItem)run(()=>inspect(sourceItem.record.sequence,offset));else readDiscoveredAttempt(group.items);
  }
  function renderWorkspace() {
    const root=$('workspace-sessions'), status=$('workspace-sources');root.replaceChildren();status.replaceChildren();
    const count=workspaceStates.reduce((n,s)=>n+s.records.length,0), complete=workspaceStates.filter(s=>s.complete).length;
    const groups=workspaceGroups(), sessions=new Map();
    let unassigned=0, invalid=0;
    for(const state of workspaceStates) {
      status.append(textNode('p',`${state.entry.binding.archive} · ${state.inspected} inspected · ${state.records.length} in window · ${state.error?'unavailable; retry scan':state.complete?'inventory end reached':'partial inventory'}`,'content-coverage'));
      unassigned+=state.records.filter(x=>x.description.kind!=='capture').length;
    }
    for(const group of groups)for(const item of effectiveItems(group.items)) {
      const link=item.description.session_link;if(!link)continue;
      if(link.state!=='claimed'){invalid++;continue;}
      const id=JSON.stringify([item.writer,item.description.observer,link.scheme,link.session]);
      if(!sessions.has(id))sessions.set(id,{id,link,writer:item.writer,observer:item.description.observer,claims:[]});
      sessions.get(id).claims.push({group,item,link});
    }
    for(const group of groups)if(fragmented(group.items)) {
      const row=textNode('p',`Fragmented metadata · ${group.items[0].description.attempt} · Archive ${group.state.entry.binding.archive} `,'content-identity');
      metadataControl(row,group.state.entry,group.items,renderWorkspace);root.append(row);
    }
    $('workspace-coverage').textContent=`${count} records in this window · ${complete}/${workspaceStates.length} archive inventories finished · ${sessions.size} explicit session groups · ${unassigned} unassigned records · ${invalid} invalid link claims. Coverage is limited to authorized sources and this window; traffic completeness is unknown.`;
    $('scan-archives').textContent=count>=1000?'Continue in a new window':count?'Continue archive scan':'Scan authorized archives';
    $('scan-archives').disabled=workspaceStates.length===0 || complete===workspaceStates.length;
    for(const session of sessions.values()) {
      const card=document.createElement('details');card.className='attempt';
      const archiveCount=new Set(session.claims.map(c=>sourceId(c.group.state.entry))).size;
      card.append(textNode('summary',`Session ${session.link.session} · ${archiveCount} archives · ${session.claims.length} link claims`));
      card.append(textNode('p',`${session.link.scheme} · Writer ${session.writer} · Observer ${session.observer}`,'content-identity'));
      const members=[...new Set(session.claims.map(c=>c.group))];
      if(members.every(g=>g.state.entry.capabilities.includes('session-content'))) {
        for(let i=0;i<members.length;i+=8) {
          const chosen=members.slice(i,i+8), read=textNode('button',`Read conversation · attempts ${i+1}–${i+chosen.length}`);
          read.addEventListener('click',()=>run(()=>readSession(session,chosen)));card.append(read);
        }
      }
      for(const {group,item,link} of session.claims) {
        const row=textNode('p',`${link.transition} · Attempt ${item.description.attempt} · Archive ${group.state.entry.binding.archive} `,'content-identity');
        if(group.state.entry.capabilities.includes('content-inspection')) {
          const read=textNode('button','Read attempt in this archive');read.addEventListener('click',()=>openWorkspace(group));row.append(read);
        }
        for(const c of item.link_sources||[{sequence:item.record.sequence,offset:'0'}]) {
          const cite=textNode('button',`Link source ${c.sequence}`);cite.addEventListener('click',()=>openWorkspace(group,group.items.find(x=>x.record.sequence===c.sequence),c.offset));row.append(cite);
        }
        if(link.parent_attempt) {
          const parents=groups.filter(g=>g.items[0].writer===item.writer && g.items[0].description.observer===item.description.observer && g.items[0].description.attempt===link.parent_attempt);
          row.append(textNode('span',parents.length?` ${parents.length} observed parent archive matches; relationship remains a claim. `:' Parent not observed in this window. '));
          for(const parent of parents) {
            const button=textNode('button',`Read parent in ${parent.state.entry.binding.archive}`);
            button.addEventListener('click',()=>openWorkspace(parent));row.append(button);
          }
          if(link.parent_attempt===item.description.attempt)row.append(textNode('span',' Self-reference; no causal ordering inferred.'));
        }
        const claims=groups.filter(g=>g.key===group.key).flatMap(g=>effectiveItems(g.items)).map(x=>x.description.session_link).filter(x=>x?.state==='claimed');
        if(new Set(claims.map(x=>JSON.stringify([x.scheme,x.session,x.parent_attempt,x.transition]))).size>1)row.append(textNode('span',' Conflicting session claims retained.'));
        card.append(row);
      }
      root.append(card);
    }
    if(!sessions.size)root.append(textNode('p','No explicit session relationships found in this window. Individual attempts remain available in archive discovery.','content-coverage'));
  }
  async function scanWorkspace() {
    if(!workspaceStates.length)return;
    const current=++workspaceRun;clearSessionReader();clearContent();clearInspector();
    if(workspaceStates.reduce((n,s)=>n+s.records.length,0)>=1000)for(const state of workspaceStates)state.records=[];
    for(const state of workspaceStates)state.error=false;
    $('scan-archives').disabled=true;$('stop-archives').disabled=false;
    let batches=0;
    try {
      while(current===workspaceRun && batches<50) {
        let advanced=false;
        for(const state of workspaceStates) {
          if(state.complete || state.error)continue;
          if(batches>=50 || workspaceStates.reduce((n,s)=>n+s.records.length,0)>=1000)return;
          const remaining=1000-workspaceStates.reduce((n,s)=>n+s.records.length,0);
          try {
            const value=await rpc({action:'proof-discover',source:sourceId(state.entry),pin:state.entry.pin,cursor:state.cursor,limit:Math.min(20,remaining)});
            if(!value || current!==workspaceRun)return;
            validateDiscovery(value);
            if(value.records.length>remaining || (value.records.length===0 && value.next!==null))throw new Error('Invalid discovery progress.');
            state.records.push(...value.records);state.inspected+=value.records.length;state.cursor=value.next;state.complete=value.next===null;
          } catch(error) {if(current!==workspaceRun)return;if(error.accessDenied)throw error;state.error=true;}
          batches++;advanced=true;renderWorkspace();$('scan-archives').disabled=true;
        }
        if(!advanced)break;
      }
    } finally {if(current===workspaceRun){renderWorkspace();$('stop-archives').disabled=true;}}
  }
  $('scan-archives').addEventListener('click',()=>run(scanWorkspace));
  $('stop-archives').addEventListener('click',()=>{workspaceRun++;cancelWork();renderWorkspace();$('stop-archives').disabled=true;notice('Archive scan stopped. Completed batches and partial coverage remain visible.');});
  $('clear-archives').addEventListener('click',()=>{cancelWork();resetWorkspace();});
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

  function lockOwner(){
    ownerEpoch++;if(ownerController)ownerController.abort();ownerToken='';ownerTargets=[];ownerPreview=null;ownerRetry=null;
    $('owner-token').value='';$('owner-controls').hidden=true;$('owner-connect').hidden=false;$('owner-maintenance').hidden=true;$('owner-lock').disabled=true;$('owner-submit').disabled=true;
    for(const id of ['owner-target','owner-operation','owner-jobs','owner-detail'])$(id).replaceChildren();$('owner-preview').textContent='';$('owner-status').textContent='Owner access locked. Running maintenance is not cancelled.';
  }
  async function ownerRpc(body){
    const current=++ownerEpoch;if(ownerController)ownerController.abort();ownerController=new AbortController();
    try{const response=await fetch('/api/owner',{method:'POST',headers:{Authorization:`Bearer ${ownerToken}`,'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'omit',cache:'no-store',signal:ownerController.signal});
      if(current!==ownerEpoch)return null;if(!response.ok){if(response.status===401||response.status===403){lockOwner();$('owner-maintenance').hidden=false;$('owner-status').textContent='Owner access refused. Reader access has not changed.';return null;}throw new Error('Owner request failed. Refresh jobs before retrying; retained outputs are not removed.');}
      const value=await response.json();return current===ownerEpoch?value:null;
    }catch(error){if(current!==ownerEpoch||error.name==='AbortError')return null;throw error;}
  }
  function ownerRun(fn){Promise.resolve().then(fn).catch(error=>{$('owner-status').textContent=error.message;$('owner-submit').disabled=!ownerPreview;});}
  function ownerOperations(){
    ownerPreview=null;$('owner-submit').disabled=true;$('owner-preview').textContent='';$('owner-operation').replaceChildren();
    const target=ownerTargets.find(t=>t.id===$('owner-target').value);
    const operations=target?.kind==='import-recovery'?['restore-import']:target?.kind==='migration'?(target.recovered?['import','reconcile-import']:['import']):target?.kind==='operations'?['rotate']:['backup','recover'];
    for(const operation of operations){const option=textNode('option',operation);option.value=operation;$('owner-operation').append(option);}
    $('owner-operation').value=operations[0];
  }
  async function ownerCatalog(){
    const value=await ownerRpc({action:'catalog'});if(!value)return;
    if(!Array.isArray(value.targets)||!Array.isArray(value.jobs))throw new Error('Invalid owner response.');
    ownerTargets=value.targets;ownerPreview=null;ownerRetry=null;$('owner-target').replaceChildren();
    for(const target of ownerTargets){const option=textNode('option',`${target.id} · ${target.kind}`);option.value=target.id;$('owner-target').append(option);}
    $('owner-target').value=ownerTargets[0]?.id||'';ownerOperations();$('owner-controls').hidden=false;$('owner-connect').hidden=true;$('owner-lock').disabled=false;
    $('owner-status').textContent=`Owner ${value.owner} · ${value.jobs.length} retained jobs · one active job · lifetime quota ${value.limits.jobs}`;$('owner-jobs').replaceChildren();
    for(const status of value.jobs){const row=textNode('article','');row.className='content-item';row.append(textNode('h3',`${status.job.contract.operation} · ${status.job.contract.target.id} · ${status.state}`));row.append(textNode('p',status.job.id,'content-identity'));
      const report=status.result?.report;
      if(report?.progress)row.append(textNode('p',`${report.progress.retained_operations}/${report.progress.total_operations} import operations queued · ${report.progress.pending_operations} awaiting acknowledgment · ${report.progress.queue_coverage_complete?'queue coverage complete':'more batches remain'}`));
      if(report?.verified_selected_file_bytes)row.append(textNode('p',`${report.files} files recovered and verified · plaintext output at ${report.destination}`));
      if(report?.recovered_selected_bytes_match)row.append(textNode('p',`${report.verified_files} recovered files match · ${report.verified_bytes} verified bytes · current source inventory matches`));
      if(report?.destination&&!report.verified_selected_file_bytes)row.append(textNode('p',`Output: ${report.destination} · activation not performed`));
      if(Array.isArray(report?.remaining_preconditions)){const list=document.createElement('ul');for(const item of report.remaining_preconditions)list.append(textNode('li',item));row.append(textNode('p','Cutover remains unapproved. Remaining checks:','content-coverage'));row.append(list);}
      if(status.state==='failed')row.append(textNode('p',status.result?.error||'Operation failed; inspect retained details.','content-warning'));
      const inspect=textNode('button','Inspect maintenance job');inspect.addEventListener('click',()=>ownerRun(async()=>{const value=await ownerRpc({action:'job',id:status.job.id});if(value){$('owner-detail').replaceChildren();details($('owner-detail'),'Retained job, result and output paths',JSON.stringify(value,null,2));}}));row.append(inspect);
      if(status.state!=='running'){const retry=textNode('button','Preview new attempt');retry.addEventListener('click',()=>{ownerRetry=status.job.id;$('owner-target').value=status.job.contract.target.id;ownerOperations();$('owner-operation').value=status.job.contract.operation;$('owner-status').textContent='Select Preview maintenance to review a new linked job. Any earlier outputs stay retained.';});row.append(retry);}$('owner-jobs').append(row);
    }
  }
  $('owner-connect').addEventListener('submit',event=>{event.preventDefault();ownerToken=$('owner-token').value;$('owner-token').value='';ownerRun(ownerCatalog);});
  $('owner-refresh').addEventListener('click',()=>ownerRun(ownerCatalog));
  $('owner-target').addEventListener('change',()=>{ownerEpoch++;if(ownerController)ownerController.abort();ownerRetry=null;ownerOperations();});
  $('owner-operation').addEventListener('change',()=>{ownerEpoch++;if(ownerController)ownerController.abort();ownerRetry=null;ownerPreview=null;$('owner-submit').disabled=true;$('owner-preview').textContent='';});
  $('owner-job-form').addEventListener('submit',event=>{event.preventDefault();ownerRun(async()=>{
    ownerPreview=null;$('owner-submit').disabled=true;const request={action:'preview',target:$('owner-target').value,operation:$('owner-operation').value,retry_of:ownerRetry};
    const value=await ownerRpc(request);if(!value)return;if(typeof value.digest!=='string'||typeof value.nonce!=='string'||!value.contract)throw new Error('Invalid owner preview.');
    ownerPreview={...request,...value};$('owner-preview').textContent=`${value.contract.effect}\n${value.contract.cancellation}\n\n${JSON.stringify(value.contract,null,2)}`;$('owner-submit').disabled=false;
  });});
  $('owner-submit').addEventListener('click',()=>ownerRun(async()=>{
    if(!ownerPreview)return;const p=ownerPreview;$('owner-submit').disabled=true;
    const result=await ownerRpc({action:'submit',target:p.target,operation:p.operation,retry_of:p.retry_of,nonce:p.nonce,preview:p.digest,wait:false});if(!result)return;
    ownerPreview=null;await ownerCatalog();$('owner-status').textContent=`Maintenance ${result.state}. Refresh to inspect retained results. Closing this tab does not roll back a running job.`;
  }));
  $('owner-lock').addEventListener('click',()=>{lockOwner();$('owner-maintenance').hidden=false;});

  function clearAnalysis(hide=false) {
    analysisDraft=null;analysisPreview=null;$('analysis-form').hidden=true;$('analysis-target').textContent='';$('analysis-preview').textContent='';$('submit-analysis').disabled=true;$('analysis-detail').replaceChildren();
    if(hide){analysisEnabled=false;analysisRecipes=[];$('analysis').hidden=true;$('analysis-jobs').replaceChildren();$('analysis-recipe').replaceChildren();$('analysis-status').textContent='';}
  }
  async function loadAnalysis() {
    const value=await rpc({action:'analysis-jobs'});if(!value)return false;
    if(!Array.isArray(value.jobs)||!Array.isArray(value.configuration?.recipes))throw new Error('Invalid analysis configuration.');
    analysisRecipes=value.configuration.recipes;$('analysis-recipe').replaceChildren();
    for(const recipe of analysisRecipes){const option=textNode('option',`${recipe.id} · ${recipe.revision} · ${recipe.purpose}`);option.value=recipe.id;$('analysis-recipe').append(option);}
    $('analysis-recipe').value=analysisRecipes[0]?.id||'';
    $('analysis-status').textContent=`${value.jobs.length} visible jobs · ${value.coverage} source checks · ${value.configuration.model} · ${value.configuration.endpoint} · one active job · lifetime quota ${value.configuration.limits.jobs}`;
    $('analysis-jobs').replaceChildren();
    for(const status of value.jobs){
      const row=document.createElement('article');row.className='content-item';row.append(textNode('h3',`${status.job.draft.recipe} · ${status.state}`));row.append(textNode('p',status.job.id,'content-identity'));
      const report=status.result?.report;
      if(report?.progress)row.append(textNode('p',`${report.progress.retained_operations}/${report.progress.total_operations} import operations queued · ${report.progress.pending_operations} awaiting acknowledgment · ${report.progress.queue_coverage_complete?'queue coverage complete':'more batches remain'}`));
      if(report?.verified_selected_file_bytes)row.append(textNode('p',`${report.files} files recovered and verified · plaintext output at ${report.destination}`));
      if(report?.recovered_selected_bytes_match)row.append(textNode('p',`${report.verified_files} recovered files match · ${report.verified_bytes} verified bytes · current source inventory matches`));
      if(report?.destination&&!report.verified_selected_file_bytes)row.append(textNode('p',`Output: ${report.destination} · activation not performed`));
      if(Array.isArray(report?.remaining_preconditions)){const list=document.createElement('ul');for(const item of report.remaining_preconditions)list.append(textNode('li',item));row.append(textNode('p','Cutover remains unapproved. Remaining checks:','content-coverage'));row.append(list);}
      if(status.state==='failed')row.append(textNode('p',status.result?.error||'Operation failed; inspect retained details.','content-warning'));
      const inspect=textNode('button','Inspect job and lineage');inspect.addEventListener('click',()=>run(()=>inspectAnalysis(status.job.id)));row.append(inspect);
      if(status.state==='running'||status.state==='queued'||status.state==='interrupted'){const cancel=textNode('button','Cancel job');cancel.addEventListener('click',()=>run(async()=>{await inspectAnalysis(status.job.id,true);await loadAnalysis();}));row.append(cancel);}
      if(status.state!=='running'&&status.state!=='queued'){const retry=textNode('button','Preview a linked retry');retry.addEventListener('click',()=>run(()=>editAnalysis(status.job.draft.cites,status.job.id,status.job.draft.recipe)));row.append(retry);}
      $('analysis-jobs').append(row);
    }
    return true;
  }
  async function inspectAnalysis(id,cancel=false){
    $('analysis-detail').replaceChildren();const value=await rpc({action:'analysis-job',id,cancel});if(!value)return;
    const root=$('analysis-detail');root.append(textNode('h3',`Job ${value.state}`));root.append(textNode('p','Derived model output · assertions are untrusted. No claims or actions were published.','content-coverage'));
    for(const block of value.result?.parsed?.content||[])if(block.type==='text'&&typeof block.text==='string')appendPagedText(root,block.text,'content-text');
    if(annotationsEnabled&&value.result) {
      const promote=textNode('button','Draft annotation from this result');promote.addEventListener('click',()=>{
        const text=(value.result.parsed?.content||[]).filter(b=>b.type==='text'&&typeof b.text==='string').map(b=>b.text).join('\n');
        editAnnotation(value.job.draft.cites,`analysis/${value.job.draft.recipe}`,null,[value.job.id]);$('annotation-text').value=text.slice(0,8192);
        if(text.length>8192)notice('Draft excerpted to the annotation limit. The complete result remains linked through job provenance.');
      });root.append(promote);
    }
    details(root,'Job declaration and lifecycle',JSON.stringify({job:value.job,terminal:value.terminal},null,2));
    details(root,'Exact inputs and provider request',JSON.stringify(value.input,null,2));details(root,'Observed provider response and failure details',JSON.stringify(value.result,null,2));
  }
  async function editAnalysis(cites,retry=null,recipe=null){
    cancelWork();clearAnalysis();if(!await loadAnalysis())return;
    analysisDraft={recipe:recipe||analysisRecipes[0]?.id,cites,retry_of:retry};$('analysis-recipe').value=analysisDraft.recipe;
    $('analysis-target').textContent=`${cites.length} exact source citations${retry?' · retry of '+retry:''}. Review the recipe and destination before starting.`;$('analysis-form').hidden=false;
  }
  $('analyze-source').addEventListener('click',()=>run(async()=>{if(!source||!isProof())return;const q=sourceRequest(selected);await editAnalysis([{source:q.source,pin:q.pin,selection:q.selection}]);}));
  $('load-analysis').addEventListener('click',()=>run(async()=>{analysisPreview=null;$('submit-analysis').disabled=true;await loadAnalysis();}));
  $('analysis-recipe').addEventListener('change',()=>{cancelWork();analysisPreview=null;$('analysis-preview').textContent='';$('submit-analysis').disabled=true;});
  $('analysis-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    if(!analysisDraft)return;analysisPreview=null;$('submit-analysis').disabled=true;analysisDraft.recipe=$('analysis-recipe').value;
    const checked=await rpc({action:'analysis-preview',draft:analysisDraft});if(!checked)return;
    if(typeof checked.digest!=='string'||typeof checked.nonce!=='string')throw new Error('Invalid analysis preview.');
    analysisPreview=checked;$('analysis-preview').textContent=`${checked.effect}\nDestination: ${checked.endpoint}\nModel: ${checked.model}\nRecipe: ${checked.recipe.id} / ${checked.recipe.revision} / ${checked.recipe.purpose}\nInput: ${checked.input_bytes} bytes · output limit ${checked.max_output_tokens} tokens\n\n${checked.recipe.instructions}`;$('submit-analysis').disabled=false;
  });});
  $('submit-analysis').addEventListener('click',()=>run(async()=>{
    if(!analysisPreview||!analysisDraft)return;const checked=analysisPreview;$('submit-analysis').disabled=true;
    const value=await rpc({action:'analysis-submit',draft:analysisDraft,preview:checked.digest,nonce:checked.nonce,wait:false});if(!value)return;
    $('analysis-form').hidden=true;analysisPreview=null;analysisDraft=null;await loadAnalysis();notice(`Analysis job ${value.state}. Refresh jobs to inspect progress and retained results.`);
  }));
  $('cancel-analysis-draft').addEventListener('click',()=>{cancelWork();clearAnalysis();});

  function invalidateAnnotation(){cancelWork();annotationPreview=null;$('save-annotation').disabled=true;$('annotation-preview').textContent='';}
  function renderAnnotationRelations(){
    $('annotation-relations').replaceChildren();annotationRelations.forEach((relation,index)=>{const row=textNode('p',`${relation.kind} → ${relation.target} `),remove=textNode('button','Remove relation');remove.type='button';remove.addEventListener('click',()=>{invalidateAnnotation();annotationRelations.splice(index,1);renderAnnotationRelations();});row.append(remove);$('annotation-relations').append(row);});
  }
  $('add-relation').addEventListener('click',()=>{const target=$('relation-target').value.trim();if(!target||annotationRelations.length>=16)return;invalidateAnnotation();annotationRelations.push({kind:$('relation-kind').value,target});$('relation-target').value='';renderAnnotationRelations();});
  async function knowledgeSubjects(subject=null){
    $('knowledge-detail').replaceChildren();if(subject===null)$('knowledge-subjects').replaceChildren();
    const value=await rpc({action:'knowledge-graph',subject,day:subject===null&&$('knowledge-mode').value==='day'});if(!value)return;
    if(!Array.isArray(value.subjects)||!Array.isArray(value.relations)||!Array.isArray(value.records))throw new Error('Invalid subject graph.');
    $('knowledge-coverage').textContent=`${value.coverage} source checks · ${value.authority}`;
    if(subject===null)for(const node of value.subjects){const button=textNode('button',`${node.subject} · ${node.kind} · ${node.declarations} declarations`);button.addEventListener('click',()=>run(()=>knowledgeSubjects(node.subject)));$('knowledge-subjects').append(button);}
    const root=$('knowledge-detail');if(subject!==null)root.append(textNode('h3',subject));
    for(const record of value.records){const note=record.declaration,section=document.createElement('article');section.className='annotation';section.append(textNode('p',`${note.author} · ${note.id}${record.corrected_by.length?' · corrected by '+record.corrected_by.join(', '):''}`,'content-identity'));appendPagedText(section,note.draft.text,'content-text');
      for(const match of note.draft.text.matchAll(/```(day-(?:atom|bridge|telos))\s*\n([\s\S]*?)```/g)){
        try{details(section,`Declared ${match[1]} structure`,JSON.stringify(JSON.parse(match[2]),null,2));}catch(_){section.append(textNode('p','Malformed process declaration remains visible in the original text.','content-warning'));}
      }
      details(section,'Attributed declaration and exact citations',JSON.stringify(note,null,2));
      if(analysisEnabled){const assess=textNode('button','Assess cited evidence');assess.addEventListener('click',()=>run(()=>editAnalysis(note.draft.cites)));section.append(assess);}root.append(section);
    }
    if(value.relations.length){const table=document.createElement('table');table.className='relation-table';const head=document.createElement('tr');for(const label of ['From','Relation','To','Assertion'])head.append(textNode('th',label));table.append(head);
      for(const edge of value.relations){const row=document.createElement('tr');for(const name of [edge.from,edge.kind,edge.to]){const cell=document.createElement('td');if(name===edge.kind)cell.textContent=name;else{const open=textNode('button',name);open.addEventListener('click',()=>run(()=>knowledgeSubjects(name)));cell.append(open);}row.append(cell);}row.append(textNode('td',`${edge.author} · ${edge.annotation}${edge.corrected_by.length?' · corrected assertion retained':''}`));table.append(row);}root.append(table);}
    if(subject!==null&&!value.records.length)root.append(textNode('p','No currently authorized declaration for this subject. A relation target does not imply that its evidence is available.','content-coverage'));
  }
  $('load-subjects').addEventListener('click',()=>run(()=>knowledgeSubjects()));
  $('knowledge-mode').addEventListener('change',()=>{cancelWork();$('knowledge-subjects').replaceChildren();$('knowledge-detail').replaceChildren();$('knowledge-coverage').textContent='View changed; browse subjects to refresh.';});

  function clearKnowledge(hide=false) {
    annotationCites=[];annotationDerivations=[];annotationRelations=[];$('annotation-relations').replaceChildren();$('relation-target').value='';annotationSupersedes=null;annotationPreview=null;
    $('annotation-form').hidden=true;$('annotation-subject').value='';$('annotation-text').value='';$('annotation-tags').value='';$('annotation-target').textContent='';$('annotation-preview').textContent='';$('save-annotation').disabled=true;
    if(hide){$('knowledge-subjects').replaceChildren();$('knowledge-detail').replaceChildren();$('knowledge-coverage').textContent='';annotationsEnabled=false;$('knowledge').hidden=true;$('annotation-list').replaceChildren();$('annotation-status').textContent='';$('annotation-filter-subject').value='';$('annotation-filter-tag').value='';}
  }
  function editAnnotation(cites,subject='',supersedes=null,derived=[],relations=[]) {
    cancelWork();clearKnowledge();annotationCites=cites;annotationDerivations=derived;annotationRelations=relations.map(r=>({...r}));renderAnnotationRelations();annotationSupersedes=supersedes;
    $('annotation-form').hidden=false;$('annotation-subject').value=subject;
    $('annotation-target').textContent=`${cites.length} evidence citation${cites.length===1?'':'s'}${supersedes?` · correction of ${supersedes}`:''}`;
    $('annotation-subject').focus();
  }
  $('annotate-source').addEventListener('click',()=>{
    if(!isProof() || selected===null)return;
    const request=sourceRequest(selected);editAnnotation([{source:request.source,pin:request.pin,selection:request.selection}]);
  });
  for(const id of ['annotation-subject','annotation-text','annotation-tags'])$(id).addEventListener('input',()=>{cancelWork();annotationPreview=null;$('save-annotation').disabled=true;$('annotation-preview').textContent='';});
  $('annotation-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    annotationPreview=null;$('save-annotation').disabled=true;$('annotation-preview').textContent='Verifying citations and authorship…';
    const draft={subject:$('annotation-subject').value.trim(),text:$('annotation-text').value.trim(),tags:$('annotation-tags').value.split(',').map(t=>t.trim()).filter(Boolean),cites:annotationCites,supersedes:annotationSupersedes,...(annotationDerivations.length?{derived_from:annotationDerivations}:{}),...(annotationRelations.length?{relations:annotationRelations}:{})};
    const checked=await rpc({action:'annotation-preview',draft});if(!checked)return;
    if(typeof checked.id!=='string' || !checked.declaration?.draft || !Array.isArray(checked.evidence))throw new Error('Invalid annotation preview.');
    annotationPreview=checked;$('annotation-preview').textContent=`Signed by ${checked.declaration.author}\n${checked.effect}\n${checked.evidence.map(e=>`${e.source} · occurrence ${e.record.sequence} · ${e.availability}`).join('\n')}\n\n${checked.declaration.draft.subject}\n${checked.declaration.draft.text}\nTags: ${checked.declaration.draft.tags.join(', ')}\nRelations: ${JSON.stringify(checked.declaration.draft.relations||[])}\n${checked.declaration.analysis_trigger_plan?.length?'Automatic analysis after append:\n'+JSON.stringify(checked.declaration.analysis_trigger_plan,null,2):'No automatic analysis scheduled.'}`;$('save-annotation').disabled=false;
  });});
  $('save-annotation').addEventListener('click',()=>run(async()=>{
    if(!annotationPreview)return;const preview=annotationPreview;$('save-annotation').disabled=true;
    const saved=await rpc({action:'annotation-save',draft:preview.declaration.draft,preview:preview.id});if(!saved)return;
    clearKnowledge();$('annotation-status').textContent=`Annotation ${saved.id} appended. Earlier evidence and notes are preserved.`;await loadAnnotations();
  }));
  $('cancel-annotation').addEventListener('click',()=>{cancelWork();clearKnowledge();});
  async function loadAnnotations() {
    $('annotation-list').replaceChildren();
    const value=await rpc({action:'annotations',subject:$('annotation-filter-subject').value.trim()||null,tag:$('annotation-filter-tag').value.trim()||null});if(!value)return;
    if(!Array.isArray(value.records) || value.records.length>1000)throw new Error('Invalid annotations.');
    $('annotation-status').textContent=`${value.records.length} authorized annotations · ${value.coverage==='partial'?'some source checks unavailable':'source access checked'}. Earlier revisions remain visible.`;
    for(const note of value.records){
      if(!note.draft || !Array.isArray(note.draft.cites) || !Array.isArray(note.draft.tags))throw new Error('Invalid annotation.');
      const row=textNode('article','');row.className='annotation';row.append(textNode('h3',note.draft.subject));row.append(textNode('pre',note.draft.text));row.append(textNode('p',`Author: ${note.author} · recorded at Unix ${note.recorded_at || 'unknown'} · ${note.id}`));if(note.draft.derived_from?.length)row.append(textNode('p',`Derived from analysis jobs: ${note.draft.derived_from.join(', ')}`));row.append(textNode('p',`Tags: ${note.draft.tags.join(', ')}${note.draft.supersedes?` · corrects ${note.draft.supersedes}`:''}`));
      for(const cite of note.draft.cites){const open=textNode('button','Inspect cited evidence');open.addEventListener('click',()=>run(async()=>{
        const entry=scopes.find(s=>sourceId(s)===cite.source);if(!entry)throw new Error('Source catalog changed.');
        choose({...entry,pin:cite.pin,pin_wire:JSON.stringify(cite.pin)});clearContent();checks.clear();buttons.clear();selections.clear();$('rows').replaceChildren();$('previous').disabled=true;$('next').disabled=true;
        const value=await rpc({action:'proof-source',...cite,offset:'0',length:'65536'});if(!value)return;
        selected=value.record.sequence;selections.set(selected,cite.selection);showSource(value);tab('source');
      }));row.append(open);}
      const publication=textNode('div','');const check=textNode('button','Check ledger publication');check.addEventListener('click',()=>run(async()=>{const value=await rpc({action:'annotation-delivery',id:note.id});if(value)renderPublication(publication,note.id,value);}));row.append(check);row.append(publication);
      if(analysisEnabled){const analyze=textNode('button','Analyze cited evidence');analyze.addEventListener('click',()=>run(()=>editAnalysis(note.draft.cites)));row.append(analyze);}
      if(note.analysis_trigger_plan?.length){
        const results=document.createElement('div'),check=textNode('button','Inspect tag-triggered jobs');
        check.addEventListener('click',()=>run(()=>showTriggers(note.id,results)));row.append(check);row.append(results);
      }
      const correct=textNode('button','Append correction');correct.addEventListener('click',()=>editAnnotation(note.draft.cites,note.draft.subject,note.id,note.draft.derived_from||[],note.draft.relations||[]));row.append(correct);$('annotation-list').append(row);
    }
  }
  async function showTriggers(id,parent,retry=false){
    const value=await rpc({action:'annotation-triggers',id,retry});if(!value)return;
    parent.replaceChildren();details(parent,'Configured tag analysis and scheduling history',JSON.stringify(value,null,2));
    const latest=value.attempts[value.attempts.length-1];
    for(const outcome of latest?.outcomes||[])if(outcome.job){const open=textNode('button',`Inspect ${outcome.recipe} job`);open.addEventListener('click',()=>run(()=>inspectAnalysis(outcome.job)));parent.append(open);}
    if(!latest||latest.outcomes.some(o=>o.state==='not-scheduled')){const again=textNode('button','Retry failed scheduling');again.addEventListener('click',()=>run(()=>showTriggers(id,parent,true)));parent.append(again);}
  }
  function renderPublication(parent,id,value) {
    parent.replaceChildren();
    if(value.state==='not-configured'){parent.append(textNode('p','Stored in this reader workspace. No ledger publication destination is configured.'));return;}
    if(!['not-queued','queued','acknowledged'].includes(value.state) || !value.destination || typeof value.destination_digest!=='string')throw new Error('Invalid publication status.');
    parent.append(textNode('p',`${value.state} · destination scope ${value.destination.scope} · issuer ${value.destination.issuer} · recipient ${value.destination.recipient} · ${value.destination.endpoint}`));
    if(value.record)parent.append(textNode('p',`Manifest: ${value.record.manifest} · writer position ${value.record.position}`));
    if(value.state==='not-queued'){
      const queue=textNode('button','Queue encrypted annotation');queue.addEventListener('click',()=>run(async()=>{const result=await rpc({action:'annotation-queue',id,destination:value.destination_digest});if(result)renderPublication(parent,id,result);}));parent.append(queue);
    } else if(value.state==='queued') {
      const deliver=textNode('button','Deliver one queued record');deliver.addEventListener('click',()=>run(async()=>{
        const result=await rpc({action:'annotation-drain',destination:value.destination_digest});if(!result)return;
        notice(`Publication queue: ${result.pending} remaining. Original queued bytes are retained until acknowledged.`);
        const status=await rpc({action:'annotation-delivery',id});if(status)renderPublication(parent,id,status);
      }));parent.append(deliver);
    }
  }
  $('load-annotations').addEventListener('click',()=>run(loadAnnotations));
  function clearSearch(hide = false) {
    searchRun++; searchStates=[]; searchFilter=null; searchHits.clear(); searchPages=0;
    $('search-results').replaceChildren();$('search-facets').replaceChildren();$('search-coverage').textContent='';
    $('saved-views').replaceChildren();$('views-status').textContent='';$('save-view').disabled=true;$('resume-search').disabled=true;$('stop-search').disabled=true;
    if(hide){for(const id of ['search-observer','search-attempt','search-from','search-to'])$(id).value='';$('search-workspace').hidden=true;$('search-text').value='';$('search-writer').value='';$('view-name').value='';}
  }
  function searchTargets(entries) {
    return entries.map(entry=>({entry:{...entry},cursor:null,complete:false,count:0,binary:0n,unavailable:0,facets:new Map()}));
  }
  function renderSearch() {
    $('search-results').replaceChildren();$('search-facets').replaceChildren();
    for(const {state,hit} of searchHits.values()) {
      const row=textNode('article','');row.className='search-result';
      row.append(textNode('p',`${state.entry.scope} · ${state.entry.binding.archive} · occurrence ${hit.record.sequence}`));
      row.append(textNode('pre',hit.snippet));row.append(textNode('p',`${hit.kind} · ${hit.writer} · ${hit.interpretation==='metadata-only'?'metadata filter; no text span matched':hit.coarse?'decoded JSON text; enclosing source':'exact UTF-8 source'} bytes ${hit.offset}–${hit.end}`));
      const open=textNode('button','Open exact source');open.addEventListener('click',()=>run(async()=>{
        searchRun++;cancelWork();choose(state.entry);clearContent();clearInspector();checks.clear();buttons.clear();selections.clear();selections.set(hit.record.sequence,hit.record.selection);
        $('rows').replaceChildren();after=0;next=null;history=[];$('previous').disabled=true;$('next').disabled=true;$('count').textContent='Search selection';$('page-position').textContent='Choose an archive to browse inventory';$('empty').hidden=true;
        $('stop-search').disabled=true;
        $('scope').value=sourceId(state.entry);await inspect(hit.record.sequence,hit.offset);
      }));row.append(open);$('search-results').append(row);
    }
    for(const state of searchStates) {
      const facets=[...state.facets].map(([k,n])=>`${k}: ${n}`).join(' · ');
      $('search-facets').append(textNode('p',`${state.entry.binding.archive}: ${state.count} indexed occurrences searched · ${state.complete?'pinned inventory scan complete':'partial scan'} · ${state.binary} unsearchable bytes · ${state.unavailable} unavailable matches${facets?' · '+facets:''}`));
    }
    $('search-coverage').textContent=`${searchHits.size} matches shown across ${searchPages} index pages. Facets reflect indexing time. Raw UTF-8 and bounded decoded strings from complete JSON spans are searched; normalized matches cite their enclosing source. Binary spans and phrases crossing chunks are excluded. Complete inventory does not prove complete capture.`;
    $('resume-search').disabled=searchStates.every(s=>s.complete);$('save-view').disabled=!searchFilter || !searchStates.length;
  }
  async function searchWindow() {
    const current=++searchRun;$('stop-search').disabled=false;$('resume-search').disabled=true;
    if(searchHits.size>=1000)searchHits.clear();
    let pages=0;
    try {
      // Round-robin bounded windows keep every chosen archive represented.
      while(pages<25 && searchStates.some(s=>!s.complete)) {
        for(const state of searchStates.filter(s=>!s.complete)) {
          if(current!==searchRun || pages>=25 || searchHits.size>=1000)return;
          const target={source:sourceId(state.entry),pin:state.entry.pin};
          const indexed=await rpc({action:'index-page',target,cursor:state.cursor});if(!indexed || current!==searchRun)return;
          const result=await rpc({action:'search-page',target,cursor:state.cursor,filter:searchFilter});if(!result || current!==searchRun)return;
          if(result.state!=='indexed' || !Array.isArray(result.hits) || result.hits.length>8 || !Number.isSafeInteger(result.indexed_occurrences) || result.indexed_occurrences>8 || !Object.hasOwn(result,'next'))throw new Error('Invalid search page.');
          for(const hit of result.hits) {
            if(!hit.record || typeof hit.record.sequence!=='string' || !hit.record.selection || typeof hit.snippet!=='string' || hit.snippet.length>1024 || !/^\d+$/.test(hit.offset) || !/^\d+$/.test(hit.end))throw new Error('Invalid search hit.');
            searchHits.set(`${target.source}:${hit.record.sequence}`,{state,hit});
          }
          state.count+=result.indexed_occurrences;state.binary+=BigInt(result.unsearchable_bytes);state.unavailable+=result.unavailable_matches;
          for(const [kind,count] of Object.entries(result.facets_as_indexed.kind))state.facets.set(kind,(state.facets.get(kind)||0)+count);
          state.cursor=result.next;state.complete=result.next===null;searchPages++;pages++;renderSearch();
        }
      }
    } finally {if(current===searchRun){$('stop-search').disabled=true;renderSearch();}}
  }
  $('search-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    cancelWork();clearSearch();
    searchFilter={text:$('search-text').value.trim(),writer:$('search-writer').value.trim()||null,kind:$('search-kind').value||null};
    if($('search-observer').value)searchFilter.observer=$('search-observer').value;
    if($('search-attempt').value.trim())searchFilter.attempt=$('search-attempt').value.trim();
    for(const [input,key] of [['search-from','attested_from'],['search-to','attested_to']])if($(input).value){const n=new Date($(input).value).getTime();if(!Number.isSafeInteger(n)||n<0)throw new Error('Invalid attestation date.');searchFilter[key]=String(n);}
    if(searchFilter.attested_from&&searchFilter.attested_to&&BigInt(searchFilter.attested_from)>BigInt(searchFilter.attested_to))throw new Error('Date range is reversed.');
    const entries=$('search-scope').value==='selected' ? [activeSource] : scopes;
    searchStates=searchTargets(entries.filter(s=>s?.protocol==='kan-proof-reader/1'));
    if(!searchStates.length){notice('No proof archive is available for this search.',true);return;}
    await searchWindow();
  });});
  $('resume-search').addEventListener('click',()=>run(searchWindow));
  $('stop-search').addEventListener('click',()=>{searchRun++;cancelWork();$('stop-search').disabled=true;renderSearch();notice('Search stopped. Completed pages remain visible; Continue resumes the same pinned view.');});
  $('save-view').addEventListener('click',()=>run(async()=>{
    const name=$('view-name').value.trim();if(!name || !searchFilter || !searchStates.length)return;
    const saved=await rpc({action:'save-view',name,targets:searchStates.map(s=>({source:sourceId(s.entry),pin:s.entry.pin})),filter:searchFilter});if(!saved)return;
    $('views-status').textContent=`Saved “${saved.name}” · ${saved.id}. This declaration preserves all selected snapshots and filters.`;
  }));
  $('load-views').addEventListener('click',()=>run(async()=>{
    $('saved-views').replaceChildren();$('views-status').textContent='Checking access to saved views…';
    const value=await rpc({action:'views'});if(!value)return;
    if(!Array.isArray(value.views) || value.views.length>200)throw new Error('Invalid views.');
    $('views-status').textContent=value.coverage==='partial'?'Some sources could not be checked. Only fully authorized views are shown.':'Views with current access to every source.';
    for(const view of value.views){
      if(typeof view.name!=='string' || !Array.isArray(view.targets) || !view.targets.length || view.targets.length>16 || !view.filter)throw new Error('Invalid view.');
      const row=textNode('article','');row.append(textNode('h3',view.name));row.append(textNode('p',`${view.filter.text} · ${view.targets.length} pinned archives · ${view.author}`));
      const open=textNode('button','Run pinned view');open.addEventListener('click',()=>run(async()=>{
        const entries=view.targets.map(t=>{const entry=scopes.find(s=>sourceId(s)===t.source);if(!entry)throw new Error('Source catalog changed.');return {...entry,pin:t.pin,pin_wire:JSON.stringify(t.pin)};});
        cancelWork();clearSearch();searchFilter=view.filter;searchStates=searchTargets(entries);
        $('search-text').value=searchFilter.text;$('search-writer').value=searchFilter.writer||'';$('search-kind').value=searchFilter.kind||'';$('search-observer').value=searchFilter.observer||'';$('search-attempt').value=searchFilter.attempt||'';
        for(const [input,key] of [['search-from','attested_from'],['search-to','attested_to']]){$(input).value='';if(searchFilter[key]){const d=new Date(Number(searchFilter[key]));if(!Number.isNaN(d.getTime()))$(input).value=new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}}
        await searchWindow();
      }));row.append(open);$('saved-views').append(row);
    }
  }));
  function sourceRequest(sequence, offset = 0) {
    if (isProof()) {
      const selection = discovered.get(String(sequence))?.record.selection || selections.get(String(sequence)); if (!selection) throw new Error('Missing verified selection.');
      return {action:'proof-source',source:sourceId(activeSource),pin,selection,offset:String(offset),length:'65536'};
    }
    return pinWire ? {action:'source-exact',pin_wire:pinWire,sequence:String(sequence),offset:String(offset),length:'65536'} : {action:'source',pin,sequence,offset,length:65536};
  }
  function textNode(tag, text, className) { const e=document.createElement(tag);e.textContent=text;if(className)e.className=className;return e; }
  function sourceLink(parent, value, input, label, offset = '0', opener = null) {
    const occurrence = value.occurrences[Number(input)]; if(!occurrence)throw new Error('Invalid Content citation.');
    const button=textNode('button',label);button.addEventListener('click',()=>run(async()=>{if(opener){await opener(occurrence,offset);return;}returnItem=button;await inspect(occurrence.record.sequence,offset);}));parent.append(button);return button;
  }
  function details(parent, title, raw) {
    const d=document.createElement('details');d.append(textNode('summary',title));appendPagedText(d,raw,'');parent.append(d);
  }
  function citationRenderer(value, stream, opener = null) {
    if(!Array.isArray(stream.citation_sets)||stream.citation_sets.length>((attemptMode||opener)?32768:2048)||!Array.isArray(stream.items))throw new Error('Invalid Content citation table.');
    let total=0;
    for(const set of stream.citation_sets){
      if(!Array.isArray(set)||(total+=set.length)>((attemptMode||opener)?32768:4096))throw new Error('Invalid Content citation table.');
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
    function links(parent, ref, label){let first;for(const c of resolve(ref)){const button=sourceLink(parent,value,c.input,`${label} ${value.occurrences[Number(c.input)].record.sequence} · ${c.bytes.join('–')}`,c.bytes[0],opener);first ||= button;}return first;}
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
  function clearSessionReader() {
    $('session-reader').hidden=true;$('session-reader-body').replaceChildren();$('session-reader-status').textContent='';
  }
  async function readSession(session, groups) {
    cancelWork();clearSessionReader();clearContent();clearInspector();
    if(groups.reduce((n,g)=>n+g.items.length,0)>1024)throw new Error('Session selection exceeds 1024 records.');
    const request={action:'proof-session',identity:{writer:session.writer,observer:session.observer,scheme:session.link.scheme,session:session.link.session},
      attempts:groups.map(g=>({source:sourceId(g.state.entry),pin:g.state.entry.pin,selections:g.items.map(i=>i.record.selection)})),format:$('content-format').value};
    notice('Reading selected conversation attempts and checking every archive…');
    const value=await rpc(request);if(!value)return;
    if(value.version!=='kan-session-content/1'||Object.keys(request.identity).some(k=>value.identity?.[k]!==request.identity[k])||!Array.isArray(value.attempts)||value.attempts.length!==groups.length)throw new Error('Invalid conversation response.');
    // Build off-screen so malformed responses cannot leave partial plaintext.
    const result=document.createElement('div');
    value.attempts.forEach((attempt,index)=>{
      const group=groups[index],content=attempt.content;
      if(attempt.source!==request.attempts[index].source||JSON.stringify(attempt.pin)!==JSON.stringify(group.state.entry.pin)||content?.version!=='kan-content/2'||!Array.isArray(content.occurrences)||content.occurrences.length>1024||!Array.isArray(content.groups)||!['claimed','unconfirmed','conflicting'].includes(attempt.membership))throw new Error('Invalid conversation attempt.');
      const selected=new Map(group.items.map(i=>[i.record.sequence,i]));
      for(const o of content.occurrences)if(!selected.has(o.record.sequence))throw new Error('Unexpected conversation occurrence.');
      const opener=(o,offset)=>openWorkspace(group,selected.get(o.record.sequence),offset);
      const card=document.createElement('section');card.className='conversation-attempt';
      card.append(textNode('h3',`Attempt ${index+1} · ${group.items[0].description.attempt}`));
      card.append(textNode('p',`Archive ${group.state.entry.binding.archive} · Session membership ${attempt.membership}`,'content-identity'));
      for(const link of attempt.links)card.append(textNode('p',`${link.transition} · ${link.parent_attempt?'Parent '+link.parent_attempt:'No parent claimed'} · Session ${link.session}`,'content-coverage'));
      if(attempt.membership!=='claimed')card.append(textNode('p','Session membership could not be confirmed consistently from the selected retained metadata.','content-warning'));
      for(const o of content.observations.filter(o=>o.kind!=='capture')){const row=textNode('p',`Unavailable or unplaced evidence: ${o.kind} ${o.reason||''} `,'content-warning');sourceLink(row,content,o.input,'Inspect source','0',opener);card.append(row);}
      for(const normalized of content.groups) {
        if(normalized.writer!==session.writer||normalized.observer!==session.observer)throw new Error('Conversation identity mismatch.');
        card.append(textNode('p',`Outcome ${normalized.terminal} · ${normalized.missing_start?'start not selected':'start selected'} · ${normalized.unconfirmed_claim?'observer reports unconfirmed capture':'capture completeness unknown'}`,'content-coverage'));
        if(normalized.ordinal_gaps.length)card.append(textNode('p',`Missing observed ordinals: ${normalized.ordinal_gaps.map(g=>g.join('–')).join(', ')} (end exclusive)`,'content-warning'));
        if(normalized.ordinals.some(o=>o.conflict)||normalized.events_after_terminal)card.append(textNode('p','Conflicting ordinals or events after terminal remain in retained lineage.','content-warning'));
        for(const direction of ['request','response']) {
          const stream=normalized[direction],section=document.createElement(direction==='request'?'details':'section');
          section.className='conversation-stream';section.append(textNode(direction==='request'?'summary':'h4',direction==='request'?'Supplied request history · may repeat earlier messages':'Observed response'));
          const citations=citationRenderer(content,stream,opener);
          if(stream.state!=='interpreted')section.append(textNode('p',`Stream ${stream.state}: ${stream.issues.map(i=>i.kind).join(', ')||'no complete selected stream'}`,'content-warning'));
          for(const item of stream.items) {
            const article=document.createElement('article');article.className='content-item';article.append(textNode('h5',`${item.role||'provider'} · ${item.kind}`));
            if(item.text!==null)appendPagedText(article,item.text,'content-text');
            if(item.issues.length)article.append(textNode('p',item.issues.join(' · '),'content-warning'));
            if(item.tool){details(article,'Accumulated tool input (derived)',item.tool.json);citations.append(article,item.tool.citation_set,'Tool input source');}
            if(item.event_json!==null)details(article,'Parsed event · Source preserves exact numbers',item.event_json);
            citations.append(article,item.citation_set,'Source');section.append(article);
          }
          citations.finish(section);card.append(section);
        }
      }
      const read=textNode('button','Inspect attempt and full lineage');read.addEventListener('click',()=>openWorkspace(group));card.append(read);result.append(card);
    });
    $('session-reader-body').replaceChildren();$('session-reader-body').append(result);$('session-reader-status').textContent=value.coverage;$('session-reader').hidden=false;
    notice('Conversation ready · supplied history and archive copies remain distinct.');
  }
  $('close-session-reader').addEventListener('click',()=>{cancelWork();clearSessionReader();});
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
      for(const m of group.metadata||[]) {
        const row=textNode('p',`${m.fragmented?'Fragmented':'Inline'} request metadata · ${m.state}${m.session_link?.state==='claimed'?` · ${m.session_link.transition} · Session ${m.session_link.session}`:''} `,'content-coverage');
        for(const c of m.sources)sourceLink(row,value,c.input,`Metadata source ${value.occurrences[Number(c.input)].record.sequence} · ${c.bytes.join('–')}`,c.bytes[0]);
        card.append(row);
      }
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
  $('content-format').addEventListener('change',()=>{cancelWork();clearSessionReader();clearContent(false);clearInspector();});

  $('connect').addEventListener('submit', event => {
    event.preventDefault(); token = $('token').value; $('token').value = ''; run(catalog);
  });
  $('retry-sources').addEventListener('click', () => run(catalog));
  $('scope').addEventListener('change', () => run(async () => { const chosen = scopes.find(s => sourceId(s) === $('scope').value); if (!chosen) return; choose(chosen); await page(0); }));
  $('resnapshot').addEventListener('click', () => run(async () => { if (!pin) return; resetWorkspace(); clearDiscovery(); clearContent(); clearInspector(); const value = await rpc(isProof() ? {action:'proof-snapshot',source:sourceId(activeSource)} : {action:'snapshot',scope:$('scope').value}); if (!value) return; if(contentEnabled && typeof value.pin_wire !== 'string') throw new Error('Missing exact snapshot.'); pin = value.pin; pinWire = value.pin_wire || null; $('discovery').hidden = !activeSource?.capabilities?.includes('attempt-discovery'); const chosen = scopes.find(s => sourceId(s) === $('scope').value); chosen.pin = pin; chosen.pin_wire = pinWire; history = []; await page(0); }));
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
