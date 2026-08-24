# SBP_LEX_main

SBP-LEX V2 is a deterministic governance and execution-control system. Its
single pipeline covers classification, licensing, governance, domains,
Aurion-15, execution gating and terminal audit. The repository currently
enforces fail-closed application-level controls; production substrate
non-bypass remains a separately evidenced deployment requirement.

## Canonical launcher

The canonical V2 application entry point is the FastAPI object `main:app`.

```powershell
python -m pip install -r requirements.lock
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

The service exposes:

- `GET /health`
- `POST /v2/evaluate`

The evaluation endpoint accepts an exact envelope with `request` and optional
`pre_context_signals` fields. Unknown top-level fields are rejected. Without
separately admitted runtime authorities and evidence providers, evaluation
fails closed.

The direct Python entry points are `main.run_sbp_lex`,
`sbp_lex.pipeline.runner.run_v2`, and
`sbp_lex.pipeline.runner.run_v2_pipeline`.
