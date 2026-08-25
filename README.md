# SBP_LEX_main

SBP-LEX V2 is a deterministic governance and execution-control system. Its
single pipeline covers classification, licensing, governance, domains,
Aurion-15, execution gating and terminal audit. The repository currently
enforces fail-closed application-level controls; production substrate
non-bypass remains a separately evidenced deployment requirement.

## Canonical library and CLI

The canonical public library entry point is `main.run_v2`. The canonical
one-shot CLI is `python main.py`. SBP-LEX V2 does not currently declare an
ASGI application, HTTP service or production web deployment.

```powershell
python -m pip install --require-hashes -r requirements-production.lock.txt
python main.py --request-json '{"action":"review","payload":{},"context":{}}'
```

The CLI accepts exactly one of `--request-json` or `--request-file`, plus
optional `--signals-json` or `--signals-file`. It intentionally exposes no
flags for injecting authority, custody, effect or deployment providers, so a
standalone invocation remains fail closed.

Library integrations that possess separately admitted dependencies call
`main.run_v2(...)` and supply them explicitly. `main.run_sbp_lex(...)` remains
only as a compatibility wrapper because repository tests, PTDE callable
inventory and existing consumers still name it. The runner implementation is
`sbp_lex.pipeline.runner.run_v2`; `run_v2_pipeline` is retained compatibility
surface, not the canonical public name.

For development and test collection:

```powershell
python -m pip install --require-hashes -r requirements-test.lock.txt
python -m pytest --collect-only -q tests
```

Current implementation, validation and blocker truth is maintained only in
[`docs/validation/V2_CANONICAL_STATUS.md`](docs/validation/V2_CANONICAL_STATUS.md).
