---
{
  "v": 3,
  "cid": "bafyreigicruw3scyp25priugczq7bxuya6ez7iyj5oon3fdrc5gzdjz5o4",
  "sig": "7e90c979a1978a5c3c62cf7fb3a44b3965ca003e9b8719a05b4d2cd08f62318c284d14856946aa19b38c336cd1f4ac7703de7dca3fca18a4b980b1260ba79a66",
  "author": "did:key:zDnaehmzfNTMdcysAxirpTSS2FdHE2NSf7s7VGirRjhsUD6SD",
  "subject": {
    "local": "design/rfc-2"
  },
  "kind": "decision",
  "cites": [
    "bafyreihvcmlbzjkttvwpxljpq7ohkpgnlnzcqqyrppq3ebsjd23dn4u4be"
  ],
  "rev": "223mt7iv6j7jl",
  "seq": 0,
  "of": 2,
  "text_len": 657,
  "content": "p2Rib2R5oWhEZWNpc2lvbqFkdGV4dGBlY2l0ZXOB2CpYJQABcRIg9RMWHKVTnWz7rS+H3HU8zVtyKEMRe+GyBkketjbynAlmYXV0aG9yomNkaWR4OWRpZDprZXk6ekRuYWVobXpmTlRNZGN5c0F4aXJwVFNTMkZkSEUyTlNmN3M3VkdpclJqaHNVRDZTRGVhZ2VudPZnc3ViamVjdKFlTG9jYWxsZGVzaWduL3JmYy0yaWFydGlmYWN0c4GhZkNvbW1pdHgoNGIyNTc3MDVlZTk0MDA3MzNmMWRlYTJlYWNlZmJhNjg4MTRmMWFmOWl3b3Jrc3BhY2WhaVdvcmtzcGFjZXhAN2M0NjYxMjE4NTJhY2QyNzk0YTUzYWVjNGM4YmE2NDZlYzU0MzJhZDhkMGY3MzMyOTM1ZDhmNjQwYzVhNjgxNmtyZWNvcmRlZF9hdBsABlkrtkeVTA=="
}
---

ATProto Lexicon ownership is separated from the kan implementation repository. The canonical schema and release repository is https://github.com/kan-tools/kan-lexicon, with schemas under lexicons/tools/kan/. kan-lexicon owns schema evolution, code-generation configuration, cross-language generated-client fixtures, and immutable releases. kan consumes a pinned immutable revision and may vendor byte-identical snapshots for offline RFC review and CI, guarded by a drift check; those snapshots are not a second publication source. Runtime protocol authority remains the namespace DID resolved through _lexicon.kan.tools and never depends on fetching GitHub.
***8<***
---
{
  "v": 3,
  "cid": "bafyreib4e43yqz2qcg7zbfrg5cs4oih3rs7qhnxxwtmcfrqg7h4qemiwfq",
  "sig": "6162795b39d4e574d54fb94d50f21cd148e50a540b342f667c3c160b34bb16f664bb4e0dd73f2719ec2232470f07f2f911830142c4fbd34671c3f6254e305b3e",
  "author": "did:key:zDnaehmzfNTMdcysAxirpTSS2FdHE2NSf7s7VGirRjhsUD6SD",
  "subject": {
    "local": "design/rfc-2"
  },
  "kind": "publication",
  "cites": [],
  "rev": "223mt7ivfz5et",
  "seq": 1,
  "of": 2,
  "content": "p2Rib2R5oWtQdWJsaWNhdGlvbqFlbGF5ZXJnR2l0VHJlZWVjaXRlc4BmYXV0aG9yomNkaWR4OWRpZDprZXk6ekRuYWVobXpmTlRNZGN5c0F4aXJwVFNTMkZkSEUyTlNmN3M3VkdpclJqaHNVRDZTRGVhZ2VudPZnc3ViamVjdKFlTG9jYWxsZGVzaWduL3JmYy0yaWFydGlmYWN0c4GhZkNvbW1pdHgoNGIyNTc3MDVlZTk0MDA3MzNmMWRlYTJlYWNlZmJhNjg4MTRmMWFmOWl3b3Jrc3BhY2WhaVdvcmtzcGFjZXhAN2M0NjYxMjE4NTJhY2QyNzk0YTUzYWVjNGM4YmE2NDZlYzU0MzJhZDhkMGY3MzMyOTM1ZDhmNjQwYzVhNjgxNmtyZWNvcmRlZF9hdBsABlkrtr+M9w=="
}
---
