# P1/P2/P3 implementation-defined V2 mechanics

Status: `AI_PROPOSED_AWAITING_APPROVAL`; classification:
`IMPLEMENTATION_DEFINED_V2`; unfrozen.

This document describes proposed repository mechanics. It does not state filed
wording, establish the substantive meaning of P1/P2/P3, appoint an authority,
or approve a policy. The existing `three_p_doctrine.py` module remains the
attested fail-closed boundary.

`three_p_policy_v2.py` is a deliberately content-neutral interpreter. It can
operate only when an external policy supplies all of the following:

- a policy identifier and version;
- effective and expiry times;
- an authority credential and allowed evidence authorities;
- lifecycle state, revision, supersession, and revocation fields;
- separate P1, P2, and P3 rules and named thresholds;
- explicit `ALL` or `ANY` decision logic covering every rule; and
- conformance fixture identifiers, input digests, and expected determinations.

The interpreter supports only mechanical comparisons (`EQ`, `GTE`, `LTE`, and
`IN`). Those operators have no substantive authority. Rule subjects, evidence
types, fields, thresholds, sources, authority appointments, policy versions,
lifecycle decisions, and fixture truth values must be explicitly adopted
through the V2 design-authority process. They may be proposed by engineering or
AI, but generation alone grants them no authority.

Missing or malformed policy, non-active lifecycle state, revocation,
supersession, suspension, ineffective or expired policy, missing resolver,
unauthorized evidence, missing evidence, and indeterminate comparisons all
produce `NOT_SATISFIED`. The adapter signs those determinations for validation
by the existing 3P boundary. A passing result constrains the repository runtime
according to supplied mechanics; it does not prove legal, constitutional,
scientific, ecological, social, deployment, or real-world validity.

## Approval boundary still required

No authoritative policy artifact or authoritative fixture set is included.
Before this adapter can represent an approved deployment policy, an explicitly
identified V2 design authority must review, approve or replace the proposed
P1/P2/P3 rules, numerical or categorical thresholds, evidence schemas and
authorities, decision logic, credential appointment, effective period,
revocation/supersession process and fixtures. This requirement does not claim
those semantics previously existed or make the repository owner responsible
for inventing them. Until approval, the only warranted use is proposed
mechanics and fail-closed test infrastructure.
