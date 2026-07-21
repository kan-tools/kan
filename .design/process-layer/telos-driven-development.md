# Telos-driven development: foundations

## Why this doc exists

This is a grounding/theory doc, not a `/design`-shaped feature doc. It captures
the conceptual model behind the process layer — the companion tool ADR-18 and
issue #24 already named but left unscaffolded — *before* any concrete scope,
REQ/AC list, or architecture gets written for it. The actual scaffolding pass
(repo, packaging, first migrated skill) should cite this doc rather than
re-deriving the theory inline. Everything here came out of a live conversation
working through the theory interactively; it's the first time any of this has
been written down, so treat it as a foundations reference to refine, not
settled architecture.

## The split

kan is a generalizable layer for **structured knowledge** that happens to work
well for software development. The process layer (working name:
`process-layer`, per this directory — the tool's actual name is still open,
see [Open threads](#open-threads)) is a generalizable layer for **structured
process** that happens to work well for software development. The two are
meant to interact tightly but stay separate per ADR-18's existing boundary
rule: kan owns durable claims and pure reads over them; the process layer
owns everything that's process, orchestration, or multi-turn interaction.

Concretely: **kan holds situated raw/evidentiary data** — the append-only,
signed, content-addressed material substrate (claims, artifacts, git
anchors). **The process layer holds teloi, their frame-contextualization,
per-frame assessments, and cross-frame reconciliation**, and computes its
assessments *over* kan's raw data rather than trusting any agent's
self-report. That's the same anti-gaming principle issue #48's adversarial
reviewer already uses (it reruns build/test/clippy itself rather than
trusting the design doc's own claims) — here it's structural rather than a
one-off review technique.

## Source: Spivak's "plausible fiction"

Grounding reference: David Spivak, ["Plausible
Fiction"](https://topos.institute/blog/2024-08-27-plausible-fiction/) (Topos
Institute, 2024-08-27).

A plausible fiction is a narrative that:
1. begins with the present world accurately depicted,
2. ends in a desired future state,
3. follows a trajectory obeying real natural/social dynamics (not magical
   thinking), and
4. has "memetic fitness" — it invites participation from the people who
   encounter it.

Spivak's mechanism is **recursive gap-filling**: a plausible fiction contains
narrative gaps, and enacting it means filling those gaps with further
plausible sub-narratives, recursively, until the fiction becomes real through
coordinated action — a self-fulfilling prophecy rather than a prediction.

Spivak explicitly gestures at applied category theory as the right
mathematical infrastructure for this but does not build it — he names it as
"a gap which remains to be filled within my own fiction." The formalization
below (weak equivalence, frames as internal topoi, teloi, bridging states as
a sheaf condition) is this project's own extension, not something lifted
from his piece.

## Teloi as weak-equivalence-class invariants

A telos is **a state of the world defined up to weak equivalence** — not a
point-target, but an invariant: some aspect of the *shape* of the world-state
that has a particular coherence. For a piece of software, distinct teloi
might be "has this interface," "actually does this thing in the world," "gets
attention/adoption" — different invariants over the *same* underlying
world-state, which is exactly why they can be in tension without either
being wrong. This mirrors a move kan's own spec already makes (identity and
status as path-spaces/posets, never collapsed to a flat value until render)
— telos-driven development applies the same discipline to the *goal* side,
not just the *state* side.

## Frames: teloi situated in an internal topos

Teloi don't live in one flat space — they're situated within a **frame of
reference**, and frames can overlap, nest hierarchically, and be in tension
with each other. A frame is best understood as an **internal topos**: an
actor's (human or agent) own internal model, carrying its own internal logic
(its own notion of what counts as a valid certificate/proof). Assessing a
telos "in my frame" means producing a certificate that's valid *inside* that
internal logic — not an absolute fact, a locally-certified one.

Comparing a telos across frames therefore isn't a category error, but it does
require something like a **geometric morphism** between the two toposes —
and there's no guarantee one exists, or that it's lossless in both
directions. This gives a precise account of why cross-agent drift is hard to
even *detect*: two agents can each hold a valid internal certificate for
"telos satisfied" that simply doesn't transport into the other's logic.

**Reconciliation.** The process layer's job w.r.t. frames is to hold: the
teloi, their frame-contextualization, the per-frame assessments/certificates,
and the *relational reconciliation* between frames, using the frame as the
base for comparison. When frames are genuinely incomparable, it holds both
independently as irreconcilable rather than forcing a merge. In practice this
is rare — frames aren't floating free; there's an implicit **shared
reality-regularities** substrate (something like: code compiles or doesn't,
tests pass or fail, an artifact exists or doesn't) that every frame factors
through at least partially, even when higher-level interpretation diverges.
This shared substrate is exactly what kan is positioned to hold as the raw
evidentiary data both frames' assessments get checked against.

## Bridging states and realizability

**Bridging states are just intermediate teloi in time** — no separate
ontological category from a "real" telos, just teloi at a shorter horizon
that telescope into longer-horizon ones.

**Realizability of a path** between two states is two-fold:
1. **Internal to a frame**: is there a continuous evolution — judged by that
   frame's own internal continuity criteria — connecting the current state to
   the bridging telos?
2. **Globally, at the orchestration layer**: the *temporal coherence* of
   those frame-internal judgments across different extended frames over
   time.

This is a **sheaf-gluing condition**: each frame's internal-continuity
judgment is a local section; a globally realizable path exists only when
those local sections agree on the overlaps between frames as time unfolds —
not merely when each frame individually believes its own leg of the path is
fine.

## The practical model: atoms and composition

The full formalization above (and its poly-functor treatment of
decomposition — positions/directions, composing systems-as-interfaces) is
itself bracketed as **a good telos for this project to formalize fully
later**, not a v1 requirement. For now, a simpler, concrete model:

- **Atoms**: discrete process units with a specific, typed
  input/output interface.
- **Composition primitives**: sequential and parallel, producing a diagram
  (a DAG, not necessarily a linear chain) of atomic steps.
- **A work unit**: take a bridging path (an intermediate telos), build a plan
  arranging atoms in a specific (possibly non-linear) arrangement, execute
  it, then assess the resulting state against whether it falls within the
  desired end state's equivalence class.

Example atoms (software-development-focused — this list is illustrative and
skewed toward what came to mind first; the underlying theory is meant to be
domain-general, but the *tool* being built now is scoped to the software
process, per the existing "kan vs. companion tool" split):

- Generative closed-loop design
- Generative build (an agent session produces code)
- Adversarial review (an agent with different context does a structured
  review — this is issue #48's atom)
- User testing
- Research / data extraction with structured process
- Moving to formal verification of specific program behavior before
  build-out
- Purpose evaluation / drift
- Meta-evaluation and atom update
- External comms / personnel orchestration and assignment to human operators

## The regularity spectrum, not an object/meta split

"Purpose evaluation/drift" and "meta-evaluation and atom update" look like a
distinct meta-level at first — they act on the teloi/frame/atom-vocabulary
itself rather than on the software artifact. But there's no privileged
meta-level: what actually varies is **substrate regularity**. Crystallized
code sits at the well-anchored end (kan's append-only log gives strong
material grounding — diffs, tests, CIDs). External human/social action sits
toward the amorphous end (weaker corroborating evidence, more frame-dependent
judgment). Revising the atom vocabulary is just an atom whose substrate
happens to be the project's own process-definition — which can itself become
more or less crystallized as the project matures. Atoms differ in how
well-grounded their assessment can be, not in what kind of thing they are.

## Atom-vocabulary versioning: per-atom, additive

The atom vocabulary is scoped **per project** and co-evolves with that
project's teloi as part of the process itself. It's versioned the same way
kan versions everything else: **per-atom and additive** (each atom
independently added/retracted; "the current vocabulary" is the live,
non-retracted fold), not as a single document superseded wholesale. This
reuses kan's existing append/fold/retract pattern rather than inventing a
second versioning mechanic, and it matches the reflexivity point above: an
"atom update" is a discrete, individually-justified action ("added atom X,
cites: `<this observation>`"), which per-atom claims give for free and a
whole-document diff doesn't.

Because atoms' interfaces compose, the process-layer tool is expected to
**check composition validity itself** as part of update logic — querying the
current live-folded atom set and verifying interfaces still compose
coherently after a change. This is a derived read over the fold, the same
shape as kan's own status/identity computation — not a new data model.

Per ADR-18's existing boundary rule, this suggests atom-vocabulary claims
likely need **no new kan `ClaimBody`/`ClaimKind` variant** — `observe` /
`plan` / `decide` / `retract` on ordinary subjects, plus `cites`, should be
sufficient. This should be confirmed concretely once the atom-vocabulary
schema is actually designed, not assumed.

## Relationship to existing kan artifacts

- **ADR-18** (`docs/DECISIONS.md`) already drew the kan/companion-tool
  boundary this whole effort lives inside.
- **Issue #24** — scaffold the companion tool — is the concrete next step
  once this foundations doc is stable enough to design against.
- **Issue #48** — the adversarial post-implementation review skill — is one
  atom in the vocabulary above ("adversarial review"), not a standalone
  one-off technique; it should be designed as an instance of the atom
  interface, not bespoke.
- **`.claude/commands/design.md`** — flagged in ADR-18 as tech debt pending
  the companion tool — is likely the first concrete instance of the
  "generative closed-loop design" atom.

## Open threads

Not yet resolved — flagged explicitly so this doc isn't read as settled:

- Whether a frame is strictly 1:1 with an actor, or a single actor can hold
  multiple simultaneous frames (e.g. "me as engineer" vs. "me as product
  owner").
- How frames, teloi, and atoms concretely surface as kan subjects/claims —
  naming conventions, which existing primitives (`cites`, `about`, subject
  naming) carry which piece of this model.
- CLI vs. MCP vs. Claude-Code-plugin shape of the process-layer tool itself
  (issue #24 leaves this open too).
- The tool's eventual name (working directory name is `process-layer`;
  picking a real name is explicitly part of the build-out, tying into what
  works alongside `kan`).
- The full poly-functor formalization of atom composition (positions/
  directions, composing systems-as-interfaces) — bracketed as future work,
  not required to start building.
