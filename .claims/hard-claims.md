---
{
  "cid": "bafyreiaev5a3r7pvhpi6f4jehnz4ybonc6uvatkyhiiodcg5yeemithcgy",
  "sig": "14d8ec9370b359964a9ccd63bf1251e53e63eedd585e7ec4ecf3ac70ef695302445107d228291530aa68f7799c1fbef2d838cf3ecb138f9a51a0f2d5e9a4a747",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Subject",
  "cites": [],
  "content": "a664626f6479a1675375626a656374a2657469746c65782c4861726420636c61696d733a2072656e64657220636c61696d7320696e746f207468652067697420747265656c7375626a6563745f6b696e6464496465616563697465738066617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---
---8<---
---
{
  "cid": "bafyreianhys2tsvc54xmntlrz74plal4lxaghuzqmqb6sjte3byrx64vhm",
  "sig": "81845963785041ac35cf4d85af10ed8529481cc6948d0b834619f629f7a3321558d7bc95ee0a5271fe841a42b0b5ad681e133974e9870591d3ce3c173cc6295a",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Decision",
  "cites": [
    "bafyreihz3m455nxdvnt3mq74s627si7gfw2hirhddlfegqdy5gv7f3uepa"
  ],
  "content": "a664626f6479a1684465636973696f6ea164746578746065636974657381d82a58250001711220f9db39deb6e3ab67b643fc97b5f923e62db47444e31aca434078e9abf2ee847866617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

The git tree is a sharing layer, not a rendering target. This is what makes a data-model change necessary and correct: publication is a decision about a subject, so it is a claim (new ClaimBody::Publication variant with a Layer enum) -- attributable, retractable, and itself publishable, so a clone can see who chose to share a subject. A local config list would be unattributable unsynced state in a system where everything else is a signed claim. It also kills the original framing's fatal flaw: a 'rendered' markdown file would have been a second, unsigned source of truth with no answer to a tampered file.
---8<---
---
{
  "cid": "bafyreicqgul3qxcrpod6x4pc7bnn2xoewimjde5ily2goeoogkmee2dpu4",
  "sig": "dae9954e518a470d37f7f5f5358713f8a8e4e5db1162cc31719c7b3b03ee92351c521072de7adbbda5c53aa27da35d8228be15d61564f2a98cabe54d259e553a",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Decision",
  "cites": [
    "bafyreihz3m455nxdvnt3mq74s627si7gfw2hirhddlfegqdy5gv7f3uepa"
  ],
  "content": "a664626f6479a1684465636973696f6ea164746578746065636974657381d82a58250001711220f9db39deb6e3ab67b643fc97b5f923e62db47444e31aca434078e9abf2ee847866617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

Wire format: one file per subject at .claims/<subject>.md, containing one YAML-frontmatter block per claim carrying the complete signed record (cid, did, sig, kind, subject, cites, artifacts) with the narrative as the markdown body. Human-legible AND a complete verifiable claim -- a reader sees prose, kan sees claims. Claims are written verbatim (same CID, same signature, same bytes as the local log): publishing copies a claim to another layer, it never creates an altered one. docs/SPEC.md section 10's 'local-only and atproto-ready are the SAME on-disk artifact' extends to git cleanly.
---8<---
---
{
  "cid": "bafyreiejawttnrgjq4rx3zgtuk2cdxw5h3hiu2hbhk7roporq2retlfecu",
  "sig": "c8fdc31b4b142da72ea8fa943fc38299b936d2e50e6e3139769bfd23fd6592a8305a5eca6cd7e0adfea743dd360494a9e373c9f7501e4143b02c8e72dc5e2da6",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Status",
  "cites": [
    "bafyreihifqe5uy7gwbp5s6z6kfcfzesexx2w3mq4duxdl6ihxqyag7wxye"
  ],
  "content": "a664626f6479a166537461747573a16576616c7565644f70656e65636974657381d82a58250001711220e82c09da63e6b05fd97b3e51445c9244bdf56db21c1d2e35f907bc30037ed7c166617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---
---8<---
---
{
  "cid": "bafyreifb4wbt5iu2mpglymszvc3552bgwjplhfv42acdag34ylrymfdw7a",
  "sig": "bffad4ba44175b130f244bd6eb2c5929bcca9b1210a09f26ffcd8df447ad36ed3bbc107eae3901ce2bbc3df4f1f3c9dfa9d25fd9832ac8d3b0bc926fbad5e71f",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Plan",
  "cites": [
    "bafyreihzydbh4nituzf3xfrfrdsvajnt4ckawbdvaxgpgxbtmzlr45nd5e"
  ],
  "content": "a664626f6479a164506c616ea164746578746065636974657381d82a58250001711220f9c0c27e3513a64bbb962588e55025b3e0940b047505ccf35c3366571e75a3e966617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

Design constraints for hard claims, to protect existing invariants: (1) projection only, generated and never hand-edited (Cargo.lock model) -- ingesting hand-edits back as claims would make git a write path into the log; (2) frontmatter carries the CID so the rendered file is verifiable against the log rather than being a parallel unsigned truth (provenance is sacred); (3) content-addressed filenames e.g. .kan/hard/<subject>/<cid>.md so hard claims are purely additive and merge-conflict-free; (4) retraction marks with retracted_by in frontmatter, never deletes -- a vanishing file contradicts both the legibility goal and 'no operation destroys a subject'; (5) needs an explicit .gitignore carve-out, since ADR-3 says .kan/ is never checked into the repo it tracks, so that reasoning must be revisited rather than quietly contradicted. Naming risk: --hard reads as 'more true' when the design depends on the log staying authoritative; --inscribe or --in-tree names the location instead.
---8<---
---
{
  "cid": "bafyreifbyjrgpr6qfhyhd2umsdqgmqjsqumdmoyas4jjhbcm6cq257i3p4",
  "sig": "38e13400e3443254517799281bb364674c8d4571e5a0cecf0ab43ecab16b6ae36dc83ad74bb030de3c5240b91063ae954bbb3e5b84e214366f8f892caa34f818",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Decision",
  "cites": [
    "bafyreihz3m455nxdvnt3mq74s627si7gfw2hirhddlfegqdy5gv7f3uepa"
  ],
  "content": "a664626f6479a1684465636973696f6ea164746578746065636974657381d82a58250001711220f9db39deb6e3ab67b643fc97b5f923e62db47444e31aca434078e9abf2ee847866617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

Sequencing: GitTree becomes M1.5 in the sync staging plan, BEFORE HostedRelay (currently M3/v0.7). Rationale: (1) src/transport.rs deliberately deferred Workspace wiring until a second real Transport implementation exists -- GitTree is that, at a fraction of HostedRelay's cost; (2) it exercises the entire multi-actor path (multiple authors, SameAs stitching, contest stage, non-SoloTrust policy) with zero infrastructure, all currently unexercised by anything real; (3) it is the first genuine test of CLAUDE.md's smell test while the cost of being wrong is still low; (4) issue #7 E2EE does NOT block it -- a git remote you already trust with your whole source tree is a different threat model from an untrusted relay intermediary; (5) issue #30 stays a release gate, not a start gate, same call the staging doc already made for HostedRelay.
---8<---
---
{
  "cid": "bafyreifdjsjnqaddq5ngonpzn22pmnpf6pxwyzh5aig4fuorsoornjykqq",
  "sig": "1861adbec12039816c1754adec55c97f9c59d9b12120ba51a6b73a333b9e19815df846ade41dc6c585c6c0ba16f93769abd2cd8214c0b600d62557db147cad16",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Result",
  "cites": [
    "bafyreiciblnkrg2wmpka7wzfqcylcltjo7gts3ddqfjzfb7veqnankqn4q"
  ],
  "content": "a664626f6479a166526573756c74a164746578746065636974657381d82a58250001711220480adaa89b5663d40fdb2580b0b12e6977cd396c6381539287f5241a06aa0de466617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478283063313465373033373631623536646361383630366561623931346538393131653765633932613669776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

The claim-vs-subject rendering fork is settled by .design/git-tree-transport.md (PR #59, merged): one file per subject accumulating one signed frontmatter block per claim. Under the sharing-layer reframe the fork partly dissolves -- signed claims are immutable, so blocks are appended and never rewritten, which makes per-subject files additive rather than conflict-prone, and a tail conflict resolves by union. Subject stays open: designed, not built. Next step is implementation as M1.5 in the sync staging plan.
---8<---
---
{
  "cid": "bafyreifypbddm3dhzr2f5kkhg7dnjwgtm7ix6loq7elokt3uyrbnamfeaa",
  "sig": "d06a620856314739a3eccf96908b8d1a747688520aa466964e71bb4bd6baad662e29e469484074c7cf2bb3383a91c225e25080430c1a5d9734704803725ce6c6",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Decision",
  "cites": [
    "bafyreihz3m455nxdvnt3mq74s627si7gfw2hirhddlfegqdy5gv7f3uepa"
  ],
  "content": "a664626f6479a1684465636973696f6ea164746578746065636974657381d82a58250001711220f9db39deb6e3ab67b643fc97b5f923e62db47444e31aca434078e9abf2ee847866617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

Divergence is handled as ordinary source divergence, not as drift to repair. Because claims are immutable and additive, a git merge keeping both sides is the CORRECT resolution, and a tail conflict is informative -- it means two actors wrote concurrently. Ships a .gitattributes union merge driver for .claims/*.md so the common case resolves automatically, and the fold's existing contest stage handles the semantics. kan never rewrites history to resolve a conflict. Verification (CID re-hash + signature check) is what makes a hand-edited file detectable rather than merely discouraged.
---8<---
---
{
  "cid": "bafyreihifqe5uy7gwbp5s6z6kfcfzesexx2w3mq4duxdl6ihxqyag7wxye",
  "sig": "d740c006c3de3a41b0375ce74e448006eb94127a0352425bcfe6a0615cffdb631e00bbb9d5e5c80590d32d1f408a14efadb709c70ba749ae7c7e9eef2621ef3a",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Observation",
  "cites": [
    "bafyreihzydbh4nituzf3xfrfrdsvajnt4ckawbdvaxgpgxbtmzlr45nd5e"
  ],
  "content": "a664626f6479a16b4f62736572766174696f6ea164746578746065636974657381d82a58250001711220f9c0c27e3513a64bbb962588e55025b3e0940b047505ccf35c3366571e75a3e966617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

Open fork in the hard-claims design: is the rendered unit a claim or a subject? One file per claim is additive and conflict-free but fragments a telos's history across files. One file per subject accumulating its claim history reads far better in a diff (you watch the telos evolve in place) but reintroduces merge conflicts. Not obvious which way this goes; it is the first thing a design pass should settle.
---8<---
---
{
  "cid": "bafyreihnqj2psonhxkrb725wmphcf3kc2esaxmoz5aungondhyshnevhsu",
  "sig": "a135c903baaf0be37228bb025a653aad1c7d331b9010373fa1c7c4e0646472de4de768756671651d195990e2ffbef00805f5a146e3f58f627c56f59a792b8bae",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Publication",
  "cites": [],
  "content": "a664626f6479a16b5075626c69636174696f6ea1656c6179657267476974547265656563697465738066617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478283063313465373033373631623536646361383630366561623931346538393131653765633932613669776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---
---8<---
---
{
  "cid": "bafyreihz3m455nxdvnt3mq74s627si7gfw2hirhddlfegqdy5gv7f3uepa",
  "sig": "9bc361a191b8eddfe64550bf379196d394d545c343c76fb5433cd6fa6401bf12451fb5bb7a3503577d2af536e6cf3b63d680bd567809aec42fdebe8113b9d16f",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Plan",
  "cites": [
    "bafyreiejawttnrgjq4rx3zgtuk2cdxw5h3hiu2hbhk7roporq2retlfecu"
  ],
  "content": "a664626f6479a164506c616ea164746578746065636974657381d82a582500017112208905a736c4c987237de4d3a2b421dedd3ece8a68e13abf173dd186a249aca41566617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

git-tree-transport (.design/git-tree-transport.md): the hard-claims idea, reframed. Publishing a claim into the committed git tree is not a rendering or a projection -- it is moving that claim to another SHARING LAYER, the same category of act as HostedRelay or atproto, with git as the substrate. So it is a Transport implementation, not a render step: signed claims serialized as YAML-frontmatter Markdown into a tracked .claims/ directory, read back as other actors' claims after an ordinary git pull, verified by CID re-hash plus signature check, and folded with no special-casing. 10 REQs, 12 ACs, no open questions.
---8<---
---
{
  "cid": "bafyreihzydbh4nituzf3xfrfrdsvajnt4ckawbdvaxgpgxbtmzlr45nd5e",
  "sig": "ac01390744d8ac6bd997265d9136b21a3e7893bb99259ddec9d4452764334d4d20f41cb35a1b04e283463668564630393de8e15f357fc9ae1c2bb6e8ebc7c738",
  "author": "did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc",
  "subject": "Local(\"hard-claims\")",
  "kind": "Observation",
  "cites": [],
  "content": "a664626f6479a16b4f62736572766174696f6ea16474657874606563697465738066617574686f72a26364696478396469643a6b65793a7a446e616562565269694b747334486b5953586b6e5964545a676d5767775268477544384c4658696d567161654a5a4663656167656e74f6677375626a656374a1654c6f63616c6b686172642d636c61696d736961727469666163747381a166436f6d6d697478286231623464343164646637356136656534646433643637336465626463633633636664643364636169776f726b7370616365a169576f726b7370616365784037633436363132313835326163643237393461353361656334633862613634366563353433326164386430663733333239333564386636343063356136383136"
}
---

Idea: 'hard claims' -- kan gains a flag (kan observe <...> --hard, naming TBD) that additionally renders the claim as a YAML-frontmatter Markdown file into the git tree under .kan/, so the claim is co-located with the code it is about, visible in git diff and PR review, and readable by someone who does not have kan installed. Motivating case: teloi naturally live inside the code as a defining telos of a module or repo. Passes ADR-18 as kan's to own either way it is read -- as a derived projection over the fold, or as a new property on a claim. Motivating precedent: docs/DECISIONS.md is already a hand-maintained hard-claim store (42 ADRs in the tree, reviewable, readable without kan), doing this by hand because kan cannot.
