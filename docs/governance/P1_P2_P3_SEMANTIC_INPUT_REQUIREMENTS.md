# P1, P2 and P3 semantic input requirements

## Status

This document records AI-proposed V2 specification options for substantive P1,
P2 and P3 evaluators. They await an explicit, bounded design-authority decision
and are not filed wording, owner-approved semantics, legal rules or scientific
authority.

The existing V2 pipeline already supplies the mechanical boundary in
`sbp_lex/governance/three_p_doctrine.py`: an external evaluator receives an
exact state snapshot and must return signed, evidence-referenced
`SATISFIED`/`NOT_SATISFIED` determinations for P1, P2 and P3. Missing,
unverifiable or non-canonical evidence fails closed.

## Proposed information model for every primitive

One proposed deterministic semantic package would define:

1. The issuing authority, authority credential, jurisdiction and lawful scope.
2. The controlled vocabulary and exact meaning of every term.
3. The version, effective time, review time and supersession/revocation rules.
4. The facts, metrics, units, baselines, time horizons and geographic scope.
5. The admitted evidence sources and the authority/provenance required for each.
6. Hard constraints, thresholds, uncertainty bounds and prohibited conditions.
7. The deterministic evaluation method, including aggregation and conflicts.
8. The exact conditions producing `SATISFIED` or `NOT_SATISFIED`.
9. The fail-closed treatment of missing, stale, conflicting or indeterminate
   evidence.
10. Positive, negative, boundary, stale-evidence, conflict and revocation
    fixtures with expected determinations.

## P1 — Planetary Stability Engine (PSE)

The AI-proposed P1 specification surface includes:

- the protected planetary systems and geographic scales;
- carbon/emissions, climate, biodiversity, atmospheric, freshwater, land,
  ocean, pollution and resource constraints admitted by a selected authority;
- the units, reference baselines, budgets, ceilings, floors and time windows;
- cumulative, irreversible and cross-boundary impact rules;
- treatment of uncertainty, incomplete observations and model disagreement;
- source datasets, model versions, update cadence and validation authorities;
- whether any exception exists, who can declare it, its maximum scope and its
  expiry; and
- the exact rule proving that every applicable constraint is satisfied.

## P2 — Population Integrity Engine (PIE)

The AI-proposed P2 specification surface includes:

- protected persons, populations, rights, interests and jurisdictions;
- dignity, safety, health, continuity, equity, non-discrimination, access,
  displacement, cohesion and socio-economic stability constraints;
- prohibited harms and the method for measuring severity, likelihood,
  distribution, duration, reversibility and cumulative impact;
- protected-class and vulnerable-population rules;
- acceptable evidence sources, privacy/minimisation requirements and rules
  preventing biometric or demographic data from independently granting rights;
- conflict and precedence rules where population interests differ;
- emergency treatment, lawful authority, review and expiry; and
- the exact rule proving that no applicable population-integrity constraint is
  breached or left unresolved.

## P3 — Permanent Sovereign Governance Cycle (PSGC)

The AI-proposed P3 specification surface includes:

- the lawful authority hierarchy and jurisdiction-resolution rules;
- the rule classes subject to continuous validation;
- lifecycle states for creation, activation, review, suspension, amendment,
  supersession, revocation and expiry;
- mandatory review triggers, maximum review intervals and trusted-time rules;
- lawful recalibration procedure, required approvals and non-coercion controls;
- authority-continuity, delegation, succession and emergency-transition rules;
- conflict-resolution and escalation rules for inconsistent authorities;
- propagation requirements for licence, token, permit and execution
  invalidation;
- audit, notice, appeal, recovery and rollback requirements; and
- the exact rule proving that the current authority/rule state remains lawful,
  current, continuous and non-superseded at the evaluation point.

## Admission boundary

Names or Boolean results alone do not make these generated proposals
authoritative. The repository can implement a selected semantic package only
after an identified V2 design authority explicitly approves or replaces its
authority model, vocabulary, evidence sources, decision rules, boundary cases
and revocation behaviour. Until that bounded decision exists, V2 retains the
current fail-closed external-evaluator boundary. This is an unresolved V2
design decision, not material the repository owner is presumed to owe.
