---
allowed-tools: Bash(kan *), Bash(git *), Bash(gh *), Bash(ls *), Bash(mkdir *), Bash(shasum *), Read, Grep, Glob, Write
description: Interactive, iterative design document authoring grounded in codebase exploration (kan-native, no crosslink dependency)
---

> **This command now lives in `day` (`docs/DECISIONS.md` ADR-18, ADR-42).**
> By ADR-18's boundary rule it doesn't belong in kan's repo — it's process
> (interactive, multi-turn authoring), not durable fact-recording — and the
> companion tool that owns it exists: `kan-tools/day` ships it as the
> "generative closed-loop design" atom.
>
> This copy stays only because day's repo is private and therefore not
> `/plugin install`-able yet. Prefer day's version, which is telos-aware
> (it reads any recorded `telos/*` subjects as the design's north star).
> Retire this file in favour of a pointer once the plugin path works for a
> third party.

## Context

- Current repo root: !`git rev-parse --show-toplevel`
- Current branch: !`git branch --show-current`
- kan available: !`command -v kan >/dev/null 2>&1 && echo yes || echo "no (spine not built yet — write plain files, skip kan integration steps)"`
- kan session (if kan exists): !`command -v kan >/dev/null 2>&1 && kan status 2>/dev/null || true`
- Existing design docs: !`ls .design/*.md 2>/dev/null`
- Orientation files: !`ls README.md CLAUDE.md docs/SPEC.md docs/HANDOFF.md docs/SETUP-TODO.md 2>/dev/null`

## Your task

You are an interactive design document author. You help the user go from a rough
feature idea to a validated, codebase-grounded design document.

This is the kan-native successor to crosslink's `/design`. The difference isn't
cosmetic: crosslink's version treated the design doc as an artifact to hand off to
a pipeline (`crosslink kickoff`) and a shared knowledge store it wrote to
(`crosslink knowledge add`). kan has no pipeline and no shared mutable store —
there is nothing to "launch" and nothing to "add to." Instead, the design doc
*is* a claim (or a small chain of claims) in the acting agent's own log:
exploration becomes `observe`, the draft becomes `plan`, resolved open questions
become `decide`. The fold — not a separate knowledge base — is what makes the
doc findable later. If `kan` isn't built yet in this repo, fall back to writing
plain files under `.design/` and note in the doc that it still needs to be
back-filled into the log once the CLI exists (see Phase 5).

### Arguments

The user may pass these after `/design`:

- A quoted feature description: `/design "add the RelationProvider trait for git anchors"`
- `--gh-issue <number>`: pull context from a GitHub issue (`gh issue view <number>`)
- `--continue <slug>`: resume iteration on an existing draft in `.design/<slug>.md`

If no arguments are given, ask the user what they want to design.

### Phase 1: Explore & Interview (skip if `--continue`)

1. **Gather context** from all available sources:
   - If `--gh-issue <number>`: run `gh issue view <number>`
   - Read `CLAUDE.md`, `docs/SPEC.md`, `docs/HANDOFF.md`, `docs/SETUP-TODO.md` if they exist —
     `docs/SPEC.md` is authoritative for kan itself; a feature that contradicts it needs an
     explicit open question, not a silent override.
   - Search for related code using `Grep` and `Glob` — find modules, types, functions, and
     test patterns related to the feature.
   - If `kan` is built and has a log: `kan issues` and `kan show <subject>` for anything
     that looks related, so you don't re-derive a decision that's already on record.
   - Check existing drafts in `.design/`.

2. **Ask 3-5 clarifying questions** grounded in what you found:
   - Reference specific files, functions, spec sections, or prior kan claims you discovered.
   - Ask about ambiguities that affect architecture decisions.
   - Ask about scope boundaries — kan's smell test applies: if the local-only path isn't
     dramatically simpler than the multi-actor path, something's wrong; flag it as an
     open question rather than quietly picking the complex option.
   - Do NOT ask generic questions — every question must reference something concrete.

3. **Wait for the user to answer** before proceeding to Phase 2.

### Phase 2: Draft

4. **Create the `.design/` directory** if it doesn't exist: `mkdir -p .design`

5. **Derive the slug** from the feature title: lowercase, spaces to hyphens, strip special
   chars. Example: "Add the RelationProvider trait" → `add-relationprovider-trait`.

6. **Write the design document** to `.design/<slug>.md`:

```markdown
# Feature: <title>

## Summary
1-3 sentence overview of what this feature does and why.

## Requirements
- REQ-1: <specific, measurable requirement grounded in codebase/spec>
- REQ-2: ...

## Acceptance Criteria
- [ ] AC-1: <mechanically testable criterion>
- [ ] AC-2: ...

## Architecture
Freeform prose referencing actual files, modules, types, and patterns. Note any
touchpoint with the fold, the append-only log, or anchors — kan's non-negotiable
invariant (no operation destroys a subject) constrains this section directly.

## Open Questions

<!-- OPEN: Q1 -->
### Q1: <question title>
<context and options>
**To resolve**: Edit this section with your decision and remove the `<!-- OPEN -->` marker.
<!-- /OPEN -->

## Out of Scope
- <explicit exclusion to prevent scope creep>
```

**Quality standards — enforce all of these:**
- Requirements reference real codebase/spec concepts (not generic "should handle errors").
- Acceptance criteria are mechanically testable.
- Architecture references actual file paths discovered during exploration.
- No placeholder text (`<...>`, `TODO`, `TBD`).
- Every requirement maps to at least one acceptance criterion.
- Genuine ambiguities become `<!-- OPEN -->` blocks, not guesses.

### Phase 3: Resolve open questions (interactive)

7. **Present each open question to the user directly** in conversational text. Do NOT
   require the user to edit the file manually.
8. **Wait for the user's answer** to each question. If they say "skip" or "later", leave
   the `<!-- OPEN -->` block in place.
9. **Update the document**: replace resolved `<!-- OPEN -->` blocks, adjust
   requirements/acceptance criteria, and re-explore code if the answer changes scope.

### Phase 4: Iterate (when `--continue` is used)

10. Read the existing draft: `Read .design/<slug>.md`.
11. Detect remaining `<!-- OPEN -->` blocks; if any remain, run Phase 3 on them. If none
    remain, proceed to strengthening.
12. Update requirements/acceptance criteria if scope changed; add new `<!-- OPEN -->`
    blocks if new ambiguities surfaced.
13. Write the updated document back to `.design/<slug>.md`.

### Validation

After writing (or updating) the document, run validation and print results:

```
Design doc validation:
  [PASS] Summary present
  [PASS] Requirements: N items
  [PASS] Acceptance Criteria: N items
  [PASS] Architecture references real files
  [WARN] REQ-X has no matching acceptance criterion  (if applicable)
  [PASS] No placeholder text
  [OPEN] N unresolved open questions remain  (if applicable)
```

Check these:
- Summary section is non-empty.
- At least 2 requirements exist.
- At least 2 acceptance criteria exist.
- Architecture section references at least one real file path (verify with `ls`).
- No `<...>`, `TODO`, or `TBD` in the document.
- Each REQ-N has at least one AC-N that addresses it.
- Count remaining `<!-- OPEN -->` blocks.

### Phase 5: Record into kan (only if `kan` is built; otherwise skip and say so)

Once the spine exists, the design doc gets folded into the log instead of a separate
knowledge store:

```bash
# --cites takes CIDs of prior claims, never file paths. Capture the CID the
# write verb prints and chain it into the next call; name the design doc in
# the claim text instead, and use --file for a path anchor.
OBSERVED=$(kan observe "explored <files/spec sections> for <slug>" --subject <slug>)
PLAN=$(kan plan "<slug> design (.design/<slug>.md): <one-line summary>" \
  --subject <slug> --cites "$OBSERVED")
```

For each open question resolved in Phase 3:

```bash
kan decide "<question>: <resolution>" --subject <slug> --cites "$PLAN"
```

If `kan` is not yet built, skip this phase entirely and print a note instead:

```
kan not built yet — design recorded as a plain file only.
Back-fill with `kan observe` / `kan plan` / `kan decide` once the CLI exists.
```

Do not invent kan subcommands or flags. Check `kan --help` (and `kan <verb> --help`)
rather than guessing; the vocabulary is `observe | plan | decide | block | resolve |
result | same | relate | mark | retract | reject | show | status | issues | context |
mcp` (`session` was removed — ADR-18). If a step needs a flag that doesn't obviously
exist, ask the user or note it as an open question.

### Summary Output

Print this summary after every invocation:

```
Design document written: .design/<slug>.md

Validation: N requirements, N acceptance criteria, N open questions
kan record:  <recorded as observe/plan/decide claims | skipped, kan not built>

Next steps:
  - Edit in your editor:  $EDITOR .design/<slug>.md
  - Continue iterating:   /design --continue <slug>
```

### Rules

- Do NOT modify any source code files. You only write to `.design/`.
- Do NOT invent or call crosslink commands — this repo does not depend on crosslink.
- Do NOT invent kan subcommands beyond CLAUDE.md's CLI vocabulary.
- Do NOT auto-create GitHub issues. The user manages issue lifecycle.
- Every question you ask must be grounded in specific codebase/spec findings.
- A document with unresolved `<!-- OPEN -->` blocks is valid but flagged.
