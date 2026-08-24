# SBP Aurion Engine Import Provenance

Source repository: `SBP0917/SBP`

Source revision inspected: `0c684ba47b6cf93e2c8ab4e7b0d756e2dae59f1a`

Imported engine mappings:

- `sbp_lex/aurion15/crisis_recognition_engine.py` -> `sbp_lex/aurion15/runtime/crisis_recognition_engine.py`
- `sbp_lex/aurion15/ecological_constraint_engine.py` -> `sbp_lex/domains/ecological_constraint_engine.py`
- `sbp_lex/aurion15/legal_conflict_resolution_engine.py` -> `sbp_lex/governance/legal_conflict_resolution_engine.py`
- `sbp_lex/aurion15/policy_simulation_engine.py` -> `sbp_lex/governance/policy_simulation_engine.py`

Supporting source files used as the basis for V2 integration:

- `sbp_lex/aurion15/base_engine.py`
- `sbp_lex/aurion15/registry.py`

V2 adaptations:

- Preserved the four engines' declared names, stages, dependencies, state reads,
  state writes, result values, and candidate actions.
- Routed package-local imports through one shared V2 `AurionEngine` contract and
  `aurion_registry` singleton.
- Added explicit alias resolution for existing V2 naming differences.
- Made unresolved dependencies observable instead of silently ignoring them.
- Added strongly connected dependency reporting so cyclic engine groups can be
  implemented as bounded deterministic convergence groups.
- Added closed-world read/write admission contracts for all 31 registered
  class engines.
- Wired all 31 engines into a dependency-ordered runtime. The five-engine
  demographic/ecological/economic/resource/societal cycle now runs until two
  consecutive declared projections are byte-identical, with an eight-iteration
  hard bound.
- An undeclared write, unresolved dependency, unreviewed cycle, state-object
  replacement, non-finite number, unsupported projection type or convergence
  timeout fails closed and is represented in the engine trace.
