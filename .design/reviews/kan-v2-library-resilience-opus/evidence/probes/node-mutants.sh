#!/bin/zsh
# UI mutants against web/library/app.js; Node tests only.
set -u
cd "${0:A:h}/../.."
M=review-evidence/probes/mutate.py
A=web/library/app.js
PARTIAL='partial catalog coverage persists while browsing and retry clears old authority'
EMPTY='incomplete empty catalog differs from complete empty and late retry cannot repaint after lock'
DENY='both authorization denial statuses lock an already open Library'
PREV='Previous is disabled immediately when leaving a later page'
MAL='malformed duplicate and inconsistent capabilities never open a Library'
DIR='all directional control families default to exact hex with explicit text access'
RETRY='malformed retry clears partially rendered capabilities and keeps recovery available'
CAP='capability matrix renders actual service capabilities without claiming unknown support'

python3 $M U01-401-not-denial $A "response.status === 401 || response.status === 403" "response.status === 403" node "$DENY"
python3 $M U02-403-not-denial $A "response.status === 401 || response.status === 403" "response.status === 401" node "$DENY"
python3 $M U03-late-reply-repaints $A "if (current !== epoch) return null;
    if (!response.ok)" "if (!response.ok)" node "$EMPTY"
python3 $M U04-late-json-repaints $A "const value = await response.json(); if (current !== epoch) return null; return value;" "const value = await response.json(); return value;" node "$EMPTY"
python3 $M U05-both-late-checks $A "const value = await response.json(); if (current !== epoch) return null; return value;
    } catch (error) { if (current !== epoch) return null; throw error; }" "const value = await response.json(); return value;
    } catch (error) { throw error; }" node "$EMPTY"
python3 $M U06-lock-keeps-coverage $A "\$('catalog-status').textContent = ''; \$('count').textContent = '';" "\$('count').textContent = '';" node "$EMPTY" "$DENY"
python3 $M U07-retry-keeps-rows $A "clearInspector(); buttons.clear(); \$('rows').replaceChildren(); \$('scope').replaceChildren();
    scopes = []" "clearInspector(); buttons.clear(); \$('scope').replaceChildren();
    scopes = []" node "$PARTIAL"
python3 $M U08-retry-keeps-source $A "clearInspector(); buttons.clear(); \$('rows').replaceChildren(); \$('scope').replaceChildren();
    scopes = []" "buttons.clear(); \$('rows').replaceChildren(); \$('scope').replaceChildren();
    scopes = []" node "$PARTIAL"
python3 $M U09-retry-keeps-pin $A "scopes = []; pin = null; history = []; after = 0; next = null;
    \$('coverage')" "scopes = []; history = []; after = 0; next = null;
    \$('coverage')" node "$PARTIAL" "$RETRY" "$EMPTY"
python3 $M U10-retry-keeps-capabilities $A "\$('capability-list').replaceChildren(); \$('catalog-status').textContent = 'Checking configured sources…';" "\$('catalog-status').textContent = 'Checking configured sources…';" node "$PARTIAL" "$RETRY"
python3 $M U11-coverage-unvalidated $A "if (value.version !== 1 || !['complete','partial'].includes(value.coverage))" "if (value.version !== 1)" node "$MAL"
python3 $M U12-partial-shown-complete $A "const partial = value.coverage === 'partial';" "const partial = false;" node "$PARTIAL" "$EMPTY"
python3 $M U13-page-clears-coverage $A "\$('count').textContent = ''; \$('coverage').textContent = ''; \$('page-position').textContent = 'Loading…';" "\$('count').textContent = ''; \$('coverage').textContent = ''; \$('catalog-status').textContent = ''; \$('page-position').textContent = 'Loading…';" node "$PARTIAL"
python3 $M U14-inspect-clears-coverage $A "notice('Verifying snapshot membership and reading source…');" "notice('Verifying snapshot membership and reading source…'); \$('catalog-status').textContent = '';" node "$PARTIAL"
python3 $M U15-previous-enabled-while-loading $A "\$('empty').hidden = true; \$('previous').disabled = true; \$('next').disabled = true;
    notice('Reading" "\$('empty').hidden = true; \$('next').disabled = true;
    notice('Reading" node "$PREV"
python3 $M U16-duplicates-allowed $A "typeof capability !== 'string' || seen.has(capability)" "typeof capability !== 'string'" node "$MAL" "$RETRY"
python3 $M U17-nonstring-allowed $A "typeof capability !== 'string' || seen.has(capability)" "seen.has(capability)" node "$MAL"
python3 $M U18-claim-unknown-available $A "state.textContent = available ? (supported.has(capability) ? 'Available' : 'Client unsupported') : 'Upcoming';" "state.textContent = available ? 'Available' : 'Upcoming';" node "$CAP"
python3 $M U19-no-alm $A '؜‎' '‎' node "$DIR"
python3 $M U20-no-lrm-rlm $A '؜‎‏' '؜' node "$DIR"
python3 $M U21-no-isolates $A '‪-‮⁦-⁩' '‪-‮' node "$DIR"
python3 $M U22-no-embeddings $A '‪-‮⁦-⁩' '‮⁦-⁩' node "$DIR"
python3 $M U23-retry-fail-keeps-caps $A "if (!pin) { \$('capability-list').replaceChildren(); \$('scope').replaceChildren(); \$('catalog-status').textContent = 'Source check failed · coverage is unknown. Retry sources.'; }" "" node "$RETRY"
python3 $M U24-empty-partial-as-complete $A "notice(partial ? 'No verified scope is available from this incomplete check. Retry sources.' : 'No currently authorized scopes.');" "notice('No currently authorized scopes.');" node "$EMPTY"
python3 $M U25-retry-not-wired $A "\$('retry-sources').addEventListener('click', () => run(catalog));" "" node "$PARTIAL" "$EMPTY" "$RETRY"
python3 $M U26-lock-no-abort $A "epoch++; if (controller) controller.abort(); controller = null; token = '';" "if (controller) controller.abort(); controller = null; token = '';" node "$EMPTY"
python3 $M U27-lock-not-aborting $A "epoch++; if (controller) controller.abort(); controller = null; token = '';" "epoch++; controller = null; token = '';" node "$EMPTY"
