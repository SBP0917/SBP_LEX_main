# SBP-LEX V2 TLA+ model

## Scope

`SBPLEXV2.tla` is a bounded safety model of one SBP-LEX V2 request traversal.
It formalizes traversal order, fail-closed evidence handling, non-bypass,
licence and permit revocation, token chronology, one-time permit claim, effect
dispatch, receipt lineage, and terminal audit handling. TLA+ is the only
formal language used here.

This model is isolated from the active Python integration. It does not execute
or modify Python, Rust, a TPM, an effect adapter, or Git history.

## Repository evidence used

The stage order is based on:

- `sbp_lex/config/pipeline_config.py`: `PIPELINE_ORDER`,
  `GOVERNANCE_TRAVERSAL_ORDER`, `HASH_CHAIN_REQUIRED_STAGES`, and the execution
  gate checks;
- `sbp_lex/pipeline/runner.py`: repeated 3P boundaries, terminal outcomes,
  distributed token issuance, execution-gate traversal, and forced terminal
  audit;
- `sbp_lex/execution/controlled_local_adapter.py`: permit mint, claim,
  immediate pre-effect verification, effect dispatch, receipt, replay, and
  revocation mechanics;
- `sbp_lex/governance/filed_lifecycle.py` and
  `docs/patent/V2_IMPLEMENTATION_DEFINED_SKG_LIFECYCLE_CONSTRUCTION.md`: the
  three separate lifecycle stages and the explicit boundary that their order
  is a V2 implementation-defined order, not a filed runtime order.

No patent doctrine, substantive lifecycle meaning, evidence threshold, legal
interpretation, or cryptographic result is introduced by the model.

The repository mapping uses 128-character lowercase SHA-512 digests. The model
keeps SHA-512 computation and format validation abstract, so a successful TLC
run does not establish cryptographic strength or Python/Rust format equivalence.

## Modelled traversal

The state machine explicitly represents all required concepts:

1. State construction.
2. 3P ingress admission and a 3P evidence boundary at every traversal stage.
3. Root authority.
4. Authenticated SKG prerequisite.
5. Procedural and evidentiary integrity.
6. PTODF.
7. Governance determination.
8. AJ-SAAF.
9. GALA.
10. ABEGF.
11. Three separately represented filed lifecycle engines: AI Obsolescence
    Lifecycle and Supersession, Civilisational Successor Intelligence
    Transition, and Structured Post-AI Era Continuity.
12. Licence root binding, validation, and revalidation.
13. Domain.
14. Aurion candidate and runtime traversal.
15. Complete token issuance and chronology verification.
16. Execution gate.
17. Effect-permit minting.
18. One-time permit claim.
19. Immediate pre-effect revalidation.
20. Effect dispatch and receipt creation.
21. Audit finalization.
22. Revocation at every reachable post-licence point.
23. Explicit DENY, ESCALATE, HALT, pending-audit, and terminal states.

The model also includes classification, GRC, and the active licence stages
because they occur in the repository's current locked order.

Token creation is distributed throughout the Python pipeline. The explicit
`TokenIssuance` state in this abstraction represents the point at which the
complete ordered bundle is available and its chronology is verified; it does
not claim that Python creates every token in one call.

## Fail-closed evidence vocabulary

The sole passing evidence status is `VALID`. `INVALID`, `UNKNOWN`,
`MALFORMED`, `MISSING`, and `INDETERMINATE` all enter a terminal HALT path and
create an audit obligation. Governance stages may also reach explicit DENY,
ESCALATE, or HALT outcomes with otherwise well-formed evidence. A general
revocation action is enabled after licence root binding at every still-running
point. A revocation invalidates the licence and permit and enters the terminal
audit path.

The model includes explicit rejected attempts to:

- skip, duplicate, or reorder stages;
- replay a consumed permit;
- roll back a recorded revocation; and
- append or substitute an audit-chain suffix as the canonical terminal audit.

## Invariants

`SBPLEXV2.cfg` checks `TypeOK` and these 22 explicit invariants:

1. `Inv01_NoEffectWithoutSatisfiedThreeP`
2. `Inv02_NoEffectWithoutAuthenticatedSKG`
3. `Inv03_NoEffectWithoutValidAuthorityState`
4. `Inv04_NoEffectWithoutMandatoryGovernance`
5. `Inv05_NoEffectWithoutThreeLifecycleStages`
6. `Inv06_NoEffectWithoutValidActiveLicence`
7. `Inv07_NoEffectAfterRevocation`
8. `Inv08_NoEffectWithoutCompleteTokenChronology`
9. `Inv09_NoEffectWithoutValidPermit`
10. `Inv10_NoEffectWithoutImmediateRevalidation`
11. `Inv11_OnlyGovernanceDeterminationCreatesAllow`
12. `Inv12_NoTokenIndependentlyGrantsExecution`
13. `Inv13_NoLifecycleSupersedesGovernance`
14. `Inv14_NoFailedMandatoryStageBypassed`
15. `Inv15_TerminalFailurePreventsLaterExecution`
16. `Inv16_RevocationIsMonotonic`
17. `Inv17_ConsumedPermitsCannotBeReplayed`
18. `Inv18_StagesCannotSkipDuplicateOrReorder`
19. `Inv19_AuditAfterTerminalDecision`
20. `Inv20_AuditSuffixCannotBecomeCanonical`
21. `Inv21_UnknownEvidenceCannotReachExecution`
22. `Inv22_EffectHasExactlyOneTraceableLineage`

The lineage invariant requires exactly one request, decision, permit, claim,
effect, receipt, and terminal-audit obligation, with every lineage identifier
bound to the same request. Between dispatch and audit finalization the audit is
an exact pending obligation; weak fairness is specified for `FinalizeAudit`.
The checked invariant proves the bound lineage and the uniqueness of a
finalized audit when present. It is not a real-time availability proof.

## TLC execution

The current repository-local reruns used:

- TLC source: the official stable TLA+ tools v1.7.4 JAR, whose SHA-1 matched
  the release-page checksum;
- TLC reported version: `TLC2 2.19 of 08 August 2024 (rev 5a47802)`;
- Java: Microsoft OpenJDK `21.0.12.1+1` LTS, 64-bit, from an archive whose
  SHA-256 matched the publisher checksum;
- host: Windows 11 x64, 12 TLC workers;
- search: breadth-first, `MSBDiskFPSet`, `DiskStateQueue`;
- heap request: `-Xmx4g` with `-XX:+UseParallelGC`.

The separately downloaded mutable TLA+ v1.8.0 artifact did not match the
checksum shown on its release page and was not used for current evidence. Exact
tool/source hashes and run metadata are recorded in
`evidence/v2/tla-model-evidence.json`.

The command, run from `formal/tla/`, was:

```powershell
java -Xmx4g -XX:+UseParallelGC -cp <path-to-tla2tools.jar> tlc2.TLC `
  -cleanup -workers auto -metadir <temporary-model-directory> `
  -config SBPLEXV2.cfg SBPLEXV2.tla
```

### Run A: current host fail-closed configuration

Exact retained configuration:

```text
RequestIds = {"request-A", "request-B"}
PermitIds = {"permit-1", "permit-2"}
MaxRevocations = 1
HostTPMAvailable = FALSE
```

Current result on 24 August 2026:

- TLC fingerprint index: 28;
- TLC seed: `8885991410109057448`;
- initial states: 2;
- generated states: 17,298;
- distinct states: 8,904;
- states left on queue: 0;
- complete graph depth: 32;
- result: no error found;
- `TypeOK`: passed;
- all 22 explicit invariants: passed;
- counterexamples: none.

This is the primary repository configuration. Because the host TPM provider
was not established as available, permit minting fails closed and the effect
path is unreachable in this run. The effect-related invariants therefore need
the separate non-vacuity run below as well.

### Run B: hypothetical TPM-admitted non-vacuity configuration

For this bounded protocol-only run, the retained
`SBPLEXV2_TPM_ADMITTED_NONVACUITY.cfg` configuration differs only by:

```text
HostTPMAvailable = TRUE
```

The primary `SBPLEXV2.cfg` remains `FALSE`. `TRUE` is an explicit model
assumption used to reach permit minting and effect
dispatch. It is not evidence that this computer's TPM, Windows key provider,
key provisioning, private-key non-exportability, signatures, or deployment
controls were validated.

Current result on 24 August 2026:

- TLC fingerprint index: 125;
- TLC seed: `-5507092425655269482`;
- initial states: 2;
- generated states: 20,968;
- distinct states: 10,788;
- states left on queue: 0;
- complete graph depth: 35;
- result: no error found;
- `TypeOK`: passed;
- all 22 explicit invariants: passed;
- counterexamples: none.

This run reaches the permit, claim, immediate-revalidation, effect, receipt,
and audit states, so the effect-path invariants are not merely vacuous under
the bounded protocol model.

## Coverage and vacuity review

The final self-review checked the model against each of the 23 requested
concepts and each of the 22 requested invariants. All 23 concepts are listed
in **Modelled traversal**, represented by named stages or explicit transition
actions, and all 22 invariant operators are both defined in `SBPLEXV2.tla` and
selected in `SBPLEXV2.cfg`.

Run A deliberately cannot reach permit minting because
`HostTPMAvailable = FALSE`; its effect-conditional invariants are vacuous in
that configuration, and this is recorded rather than treated as an effect-path
proof. Run B changes only that environmental model constant, completes the
full breadth-first graph to depth 35, and reaches the success path through
permit, one-time claim, immediate revalidation, dispatch, receipt, and audit.
It exercises invariants 1-10, 12, 14, 17, 21, and 22 with an effect present.
The complete graph also explores enabled revocation, replay, traversal-bypass,
and audit-suffix rejection actions. The audit-lineage property remains a
safety invariant over an exact pending audit obligation plus a finalized
artifact; eventual real-world scheduling remains outside the claim.

## Counterexamples and corrections

Neither completed TLC run produced an invariant violation or a behavior
counterexample. No counterexample has been concealed or reclassified.

Before the completed runs, static review corrected record-field references in
TLA+ `EXCEPT` expressions so they referred to `state.requestId` and
`state.revocationSequence` rather than an invalid use of the local `@` value.
No completed TLC result was discarded because of that authoring correction.
The first successful fail-closed run also reported the JVM garbage-collector
recommendation; the final recorded run added `-XX:+UseParallelGC` and produced
the same state counts.

## Modelling limits

- This is a bounded model of one active request traversal with two possible
  request identifiers, two possible permit identifiers, and one revocation
  increment. It is not an unbounded proof and does not model concurrent
  requests or distributed replicas.
- 3P is an abstract `VALID` predicate at ingress and every stage. The model
  proves ordering and fail-closed dependence on that predicate, not the
  substantive truth of P1, P2, or P3.
- SKG, authority, procedural, framework, lifecycle, licence, token, SHA-512
  digest, signature, audit, and permit verification are abstract validity
  predicates.
  TLC does not prove cryptographic algorithms, canonical byte equivalence,
  evaluator correctness, legal correctness, or evidence authenticity.
- The three lifecycle stages use the repository's V2 implementation-defined
  order. The model does not attribute that runtime order to the filed patent.
- Aurion candidate retries are represented by the ordered candidate and
  runtime stages, not by all 12 concrete loop iterations.
- Time, token expiry, permit TTL, clock rollback, process crashes, durable
  database transactions, filesystem behavior, and network partitions are not
  modelled.
- The audit suffix model records whether an appended or substituted suffix is
  accepted as canonical. It does not implement or prove a cryptographic hash
  function.
- Weak fairness expresses that an enabled terminal audit should eventually be
  finalized. The checked properties are safety invariants; deployment
  scheduling and availability remain external.
- A successful TLC result means no invariant violation was found in the exact
  bounded state spaces above. It is not a production-security certification
  and does not establish TPM enforcement.
