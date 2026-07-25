"""RakshakAI v2 dataset preparation pipeline.

Modules:
  download     - pull BigVul, Devign, PrimeVul, SecurityEval, Juliet, GHSA, OWASP
  cwe_normalize - MITRE CWE label canonicalization
  clean        - per-source record normalization
  dedup        - MinHash LSH deduplication
  to_instruct  - convert to 9-field chat-template instruction format
  pack         - tokenize + sample-pack to 4096-token shards
  validate     - JSON-schema + content sanity checks
  orchestrate  - run all stages
  utils        - shared helpers
"""
