(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let token = '', epoch = 0, controller, scopes = [], pin, after = 0, next = null, history = [], selected = null, source = null, hexadecimal = false;
  const buttons = new Map(), exports = new Map(), contentSelection = new Set(), checks = new Map();
  let pinWire = null, contentEnabled = false, contentValue = null, returnItem = null;
  function releaseExport(url) { clearTimeout(exports.get(url)); exports.delete(url); URL.revokeObjectURL(url); }
  function notice(text, error = false) { $('notice').textContent = text; $('notice').className = `notice${error ? ' error' : ''}`; }
  function clearContent(clearSelection = true) {
    contentValue = null; returnItem = null; $('content-panel').replaceChildren(); $('content-tab').disabled = true;
    if (clearSelection) { contentSelection.clear(); for (const check of checks.values()) check.checked = false; }
    updateSelection();
  }
  function updateSelection() {
    $('content-count').textContent = `${contentSelection.size} selected`;
    $('interpret').disabled = !contentEnabled || !pinWire || contentSelection.size === 0;
    $('clear-content').disabled = contentSelection.size === 0;
  }
  function cancelWork() { epoch++; if (controller) controller.abort(); }
  function clearInspector() {
    source = null; selected = null; $('source-tab').disabled = true; $('provenance-tab').disabled = true; $('inspection').hidden = true; $('source').textContent = '';
    $('provenance').replaceChildren(); $('range').textContent = ''; $('selection').textContent = 'Select an occurrence';
    $('source-hint').textContent = 'Read exact retained bytes alongside their provenance.'; $('close-inspector').hidden = true;
    for (const button of buttons.values()) button.setAttribute('aria-pressed', 'false');
  }
  function lock(message = 'Locked · connect to browse authorized evidence.') {
    for (const url of exports.keys()) releaseExport(url);
    epoch++; if (controller) controller.abort(); controller = null; token = ''; scopes = []; pin = null; history = []; after = 0; next = null;
    pinWire = null; contentEnabled = false; clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren(); $('capability-list').replaceChildren(); $('coverage').textContent = '';
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
    else { clearContent(); clearInspector(); if (!pin) { $('capability-list').replaceChildren(); $('scope').replaceChildren(); $('catalog-status').textContent = 'Source check failed · coverage is unknown. Retry sources.'; $('catalog-status').className = ''; } notice(message, true); }
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
    source = value; $('source-tab').disabled = false; $('provenance-tab').disabled = false; $('inspection').hidden = false; $('close-inspector').hidden = false;
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
    const value = await rpc(sourceRequest(sequence, offset)); if (!value) return;
    showSource(value); tab('source'); $('source-tab').focus();
  }
  async function page(position) {
    clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren();
    $('count').textContent = ''; $('coverage').textContent = ''; $('page-position').textContent = 'Loading…';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    notice('Reading the selected snapshot…');
    const value = await rpc(pinWire ? {action:'content-page',pin_wire:pinWire,after:String(position),limit:20} : {action:'page', pin, after:position, limit:20}); if (!value) return;
    after = position; next = value.next; buttons.clear(); $('rows').replaceChildren();
    for (const row of value.records) {
      const button = document.createElement('button'); button.className = 'occurrence'; button.setAttribute('aria-pressed','false');
      const title = document.createElement('strong'), id = document.createElement('span'); title.textContent = `Occurrence ${row.sequence}`; id.textContent = row.manifest;
      button.append(title); button.append(id); button.addEventListener('click', () => run(() => inspect(row.sequence))); buttons.set(row.sequence,button);
      if (contentEnabled && pinWire) {
        const wrap = document.createElement('div'), check = document.createElement('input'); wrap.className = 'selectable-occurrence';
        check.type = 'checkbox'; check.setAttribute('aria-label', `Select occurrence ${row.sequence} for Content`); checks.set(row.sequence,check);
        check.addEventListener('change', () => { cancelWork(); clearContent(false); clearInspector(); if(check.checked)contentSelection.add(String(row.sequence));else contentSelection.delete(String(row.sequence));updateSelection(); });
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
    const labels = {'snapshot-inventory':'Snapshot inventory','source-ranges':'Source ranges','provenance':'Provenance','content-inspection':'Selected Content','semantic-search':'Search','normalized-sessions':'Sessions','annotations':'Annotations','saved-views':'Saved views','analysis':'Analysis','administrative-jobs':'Admin jobs'};
    const supported = new Set(['snapshot-inventory','source-ranges','provenance','content-inspection']), seen = new Set();
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
      if (entry.pin_wire !== undefined && (typeof entry.pin_wire !== 'string' || !entry.pin_wire.length || entry.pin_wire.length > 12000)) throw new Error('Invalid exact snapshot.');
      seen.add(entry.scope);
    }
  }
  async function catalog() {
    clearContent(); checks.clear(); clearInspector(); buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren();
    pinWire = null; contentEnabled = false;
    scopes = []; pin = null; history = []; after = 0; next = null;
    $('coverage').textContent = ''; $('count').textContent = ''; $('page-position').textContent = '';
    $('empty').hidden = true; $('previous').disabled = true; $('next').disabled = true;
    $('capability-list').replaceChildren(); $('catalog-status').textContent = 'Checking configured sources…';
    notice('Checking scope access…');
    const value = await rpc({action:'catalog'}); if (!value) return;
    if (value.version !== 1 || !['complete','partial'].includes(value.coverage)) throw new Error('Unsupported reader version or coverage.');
    validateScopes(value.scopes);
    renderCapabilities(value);
    contentEnabled = value.capabilities.includes('content-inspection');
    if (contentEnabled && value.scopes.some(s => typeof s.pin_wire !== 'string')) throw new Error('Missing exact snapshot.');
    $('content-support').textContent = contentEnabled ? 'Select captures on this page. Interpretation covers only this selection.' : 'Content inspection is unavailable on this reader.';
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
    $('scope').value = scopes[0].scope; pin = scopes[0].pin; pinWire = scopes[0].pin_wire || null; await page(0);
  }

  function sourceRequest(sequence, offset = 0) {
    return pinWire ? {action:'source-exact',pin_wire:pinWire,sequence:String(sequence),offset:String(offset),length:'65536'} : {action:'source',pin,sequence,offset,length:65536};
  }
  function textNode(tag, text, className) { const e=document.createElement(tag);e.textContent=text;if(className)e.className=className;return e; }
  function sourceLink(parent, value, input, label, offset = '0') {
    const occurrence = value.occurrences[Number(input)]; if(!occurrence)throw new Error('Invalid Content citation.');
    const button=textNode('button',label);button.addEventListener('click',()=>run(async()=>{returnItem=button;await inspect(occurrence.record.sequence,offset);}));parent.append(button);
  }
  function details(parent, title, raw) {
    const d=document.createElement('details');d.append(textNode('summary',title));d.append(textNode('pre',raw));parent.append(d);
  }
  function showContent(value) {
    if(value.version!=='kan-content/1'||value.pin_wire!==pinWire||!Array.isArray(value.occurrences)||value.occurrences.length>40||!Array.isArray(value.observations)||!Array.isArray(value.groups))throw new Error('Unsupported Content response.');
    contentValue=value;$('content-panel').replaceChildren();$('content-tab').disabled=false;
    $('inspection').hidden=false;$('close-inspector').hidden=false;$('selection').textContent='Selected Content';
    $('source-hint').textContent='Observed content · roles and outcomes are claims. Follow citations to verified retained source.';
    const panel=$('content-panel');panel.append(textNode('p',value.coverage,'content-coverage'));
    const unplaced=value.observations.filter(o=>o.kind!=='capture');
    if(unplaced.length){const section=document.createElement('section');section.className='content-unplaced';section.append(textNode('h3','Other selected evidence'));for(const o of unplaced){const row=document.createElement('p');row.append(textNode('span',`${o.kind}${o.reason?' · '+o.reason:''} `));sourceLink(row,value,o.input,'Inspect source');section.append(row);}panel.append(section);}
    if(!value.groups.length)panel.append(textNode('p','No recognized capture groups in this selection. Every input remains inspectable in Source.'));
    for(const group of value.groups){
      const card=document.createElement('section');card.className='content-group';
      card.append(textNode('h3',`${group.observer} · ${group.terminal}`));card.append(textNode('p',group.attempt,'content-identity'));
      const flags=[];if(group.missing_start)flags.push('Start not selected');if(group.events_after_terminal)flags.push('Events after terminal');if(group.unconfirmed_claim)flags.push('Observer reports unconfirmed capture');
      if(group.ordinal_gaps.length)flags.push(`No recognized capture at ordinals ${group.ordinal_gaps.map(r=>r.join('–')).join(', ')} (end exclusive)`);
      if(group.ordinals.some(o=>o.conflict))flags.push('Conflicting ordinal · both streams withheld conservatively');
      if(flags.length)card.append(textNode('p',flags.join(' · '),'content-warning'));
      const lineage=document.createElement('details');lineage.className='content-lineage';lineage.append(textNode('summary','Retained occurrence lineage'));
      for(const ordinal of group.ordinals){const row=document.createElement('p');row.append(textNode('span',`Observed ordinal ${ordinal.value}${ordinal.conflict?' · conflict':''} `));for(const input of ordinal.inputs)sourceLink(row,value,input,`Source ${value.occurrences[Number(input)].record.sequence}`);lineage.append(row);}card.append(lineage);
      for(const direction of ['request','response']){
        const stream=group[direction],section=document.createElement('section');section.className='content-stream';section.append(textNode('h4',direction==='request'?'Request · supplied history':'Response · observed output'));
        if(stream.state!=='interpreted')section.append(textNode('p',`No readable stream: ${stream.issues.map(i=>i.kind+(i.bytes?' '+i.bytes.join('–'):'')).join(', ')||'absent, incomplete or contradictory selected bytes'}.`,'content-warning'));
        else {
          if(stream.coherent_stop_observed)section.append(textNode('p','Coherent protocol stop observed · capture completeness is unknown.','content-coverage'));
          for(const item of stream.items){const entry=document.createElement('article');entry.className='content-item';entry.append(textNode('h5',`${direction==='request'?'Supplied history · ':''}${item.role?item.role+' · ':''}${item.kind}${item.index!==null?' · block '+item.index:''}`));
            if(item.text!==null)entry.append(textNode('pre',item.text,'content-text'));
            if(item.issues.length)entry.append(textNode('p',item.issues.join(' · '),'content-warning'));
            if(item.pointer!==null)entry.append(textNode('p',`Parsed JSON location ${item.pointer||'/'}`,'content-pointer'));
            if(item.event_json!==null)details(entry,'Parsed event · numbers may be rounded; Source preserves exact bytes',item.event_json);
            if(item.tool){details(entry,'Accumulated tool input (derived)',item.tool.json);const refs=document.createElement('div');refs.className='content-citations';refs.append(textNode('span',`Enclosing tool block ${item.tool.region.join('–')} · coarse attribution · end exclusive`));for(const c of item.tool.citations)sourceLink(refs,value,c.input,`Tool input source ${value.occurrences[Number(c.input)].record.sequence} · ${c.bytes.join('–')}`,c.bytes[0]);entry.append(refs);}
            const sources=document.createElement('div');sources.className='content-citations';sources.append(textNode('span',`Enclosing bytes ${item.region.join('–')} · ${item.coarse?'coarse attribution':'attribution'} · end exclusive`));
            for(const citation of item.citations)sourceLink(sources,value,citation.input,`Source ${value.occurrences[Number(citation.input)].record.sequence} · ${citation.bytes.join('–')}`,citation.bytes[0]);
            entry.append(sources);section.append(entry);
          }
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
    const value=await rpc({action:'content',pin_wire:pinWire,sequences:[...contentSelection],format:$('content-format').value});if(!value)return;
    showContent(value);updateSelection();
  }));
  $('clear-content').addEventListener('click',()=>{cancelWork();clearContent();clearInspector();notice('Content selection cleared.');});
  $('content-format').addEventListener('change',()=>{cancelWork();clearContent(false);clearInspector();});

  $('connect').addEventListener('submit', event => {
    event.preventDefault(); token = $('token').value; $('token').value = ''; run(catalog);
  });
  $('retry-sources').addEventListener('click', () => run(catalog));
  $('scope').addEventListener('change', () => run(async () => { const chosen = scopes.find(s => s.scope === $('scope').value); if (!chosen) return; pin = chosen.pin; pinWire = chosen.pin_wire || null; history = []; await page(0); }));
  $('resnapshot').addEventListener('click', () => run(async () => { if (!pin) return; clearContent(); clearInspector(); const value = await rpc({action:'snapshot',scope:$('scope').value}); if (!value) return; if(contentEnabled && typeof value.pin_wire !== 'string') throw new Error('Missing exact snapshot.'); pin = value.pin; pinWire = value.pin_wire || null; const chosen = scopes.find(s => s.scope === $('scope').value); chosen.pin = pin; chosen.pin_wire = pinWire; history = []; await page(0); }));
  $('next').addEventListener('click', () => run(async () => { if (next === null) return; history.push(after); await page(next); }));
  $('previous').addEventListener('click', () => run(async () => { if (history.length) await page(history.pop()); }));
  $('more').addEventListener('click', () => run(async () => { if (source && source.next !== null) await inspect(selected,source.next); }));
  $('download').addEventListener('click', () => run(async () => {
    if (!source) return; const offset = source.offset, sequence = selected;
    // Export rechecks authorization; the displayed range is not an offline grant.
    const value = await rpc(sourceRequest(sequence,offset)); if (!value) return;
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
