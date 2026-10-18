# Kan Studio design preview

Open `preview.html` in a browser. It is a self-contained design artifact with
embedded CSS/JavaScript, system fonts, synthetic fixtures and no network calls.
The split sources are `index.html`, `studio.css` and `studio.js`.

## Included interactions

- Library: local search, project/type/gap filters and selected-record inspector.
- Sessions: message/source/provenance tabs and session switching.
- Knowledge: synthetic annotations, assertion inspection and relation explanation.
- Saved views: example selections that reopen the filtered Library.
- Analysis: run lineage, assessment and scheduling-plan concepts.
- Operations: current/retrying/full/disconnected/empty examples, gap filtering and
  attempt inspection; current health and retained gaps are distinct.
- Storage, Migration, Access: retained generations, recovery coverage, import
  source failures, grant boundaries and plan previews.
- Mobile record inspector, keyboard dialog close/focus return, and preview lock.

Annotations exist only in tab memory. No action signs records, starts a job,
rotates storage, reads live data, changes a grant or calls a provider. The full
application design requires real authenticated integrations, including privileged
admin task execution; the prototype does not implement those APIs.

## Browser verification — 2026-10-18

Checked in the Codex in-app browser using a temporary loopback server that served
only the three split design assets:

- All nine primary areas rendered; search, gap filtering, session representation
  switching, synthetic annotation creation and Knowledge rendering worked.
- Full-journal and disconnected designs preserved historical gaps and labeled
  unavailable freshness; rotation-plan dialog showed its non-executing boundary.
- Lock removed the main content; unlock returned to synthetic preview.
- Keyboard Enter opened the coverage dialog; Escape closed it and restored focus.
- All areas checked at 390px had no document-level horizontal overflow after the
  Storage & Recovery grid fix. Library was also checked at 1440px and Storage at
  768px. Large tables retain an internal scrolling region.
- Mobile row selection opened an inspector dialog. Browser error/warning logs
  were empty at the final inspected checkpoint.
- `node --check studio.js` passed. This is not a production security, accessibility
  or contrast certification; future runtime ACs remain unchecked.

Screenshots in `screenshots/` show desktop Library, Sessions and Operations,
and mobile Library and Operations. Every screenshot uses synthetic data.

The design documents are `../kan-v2-human-frontend.md` (whole product) and
`../kan-v2-operations-polish.md` (six review follow-ups). The reader deployment
question remains explicit until the user answers it. Design/bridge backfill into
legacy kan remains pending under the existing partial-trust limitation.

## Design validation

The two retained `*-validation.txt` files are the raw `day design check` outputs.
Required sections, mappings and placeholder checks pass (12/10 requirements/ACs
for the full frontend; 10/10 for operations). One reader-placement question is
open. Day runs from the main checkout because of the existing linked-worktree
limitation, so it warns about v2 paths relative to that older checkout. Every
path in those warnings was separately confirmed to exist in this design worktree.
The two withheld-claim warnings remain real and unresolved. Runtime acceptance
criteria are not checked off by this document validation.
