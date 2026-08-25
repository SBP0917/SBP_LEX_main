# SBP-LEX V2 Authority and Provenance Register

Status: `CURRENT_REPOSITORY_PROVENANCE_CONTROL`

Assessment date: 24 August 2026

## Purpose

This register is the current source-of-truth for how SBP-LEX V2 requirements
may be attributed. It separates filed text, owner decisions, AI-generated or
otherwise unsupported proposals, repository-defined mechanics, and facts that
can exist only in a real deployment.

This register does not make a patent-status determination or convert repository
code into owner approval. It records one bounded `OWNER_APPROVED_V2_DESIGN`
item: the strict ML-DSA-87 AND Ed448 signature/custody decision in
`V2_STRICT_DUAL_SIGNATURE_DECISION.md`. No approval is inferred for any other
design below.

## Controlling classification rules

| Classification | Admission rule |
|---|---|
| `EXACT_FILED_WORDING` | Verbatim wording must be matched directly to an admitted primary filing artifact, with an exact document location and content digest. A secondary summary, filename, historical digest, owner-identified label, or code constant is insufficient. |
| `OWNER_APPROVED_V2_DESIGN` | A specific V2 design must have an explicit, attributable and dated owner decision identifying exactly what was approved. A request to continue work, clean the repository, or implement a bounded task is not approval of every earlier generated concept. |
| `AI_PROPOSED_AWAITING_APPROVAL` | Default for generated, inferred, condensed, reconstructed or otherwise unsupported architecture, semantics, inventories, policies, algorithms, evidence criteria or attribution. This classification does not assert that AI origin has been forensically proven; it prevents unsupported material from being treated as owner-approved or authoritative. |
| `IMPLEMENTATION_DEFINED_V2` | A schema, interface, ordering rule, identifier, algorithm or fail-closed mechanic that is actually defined by repository source. This proves only that the repository defines the mechanic. It does not prove owner approval, filed origin, semantic truth, correct execution, production deployment or patent conformance. |
| `EXTERNAL_PHYSICAL_DEPENDENCY` | A real-world dependency outside repository source, such as a provisioned HSM/TPM, trusted issuer, authoritative legal corpus, durable production store, enforced adapter route or independent validating organisation. An interface, fixture, mock or plan does not satisfy it. |

If two classifications appear to apply, the subject must be split. For example,
an HSM interface can be `IMPLEMENTATION_DEFINED_V2`, the choice to require a
particular HSM/algorithm can be `AI_PROPOSED_AWAITING_APPROVAL`, and the real
device, key and attestation are an `EXTERNAL_PHYSICAL_DEPENDENCY`.

## Source boundary found in this workspace

- No admitted primary artifact for `ORIGINAL 1ST SUBMITTED SBP-LEX 20 PATENT
  CLAIMS.pdf` or `FINAL MASTER SPEC 4_3_26 LAST EVER.pdf` is present in the
  inspected repository tree.
- A temporary review copy of the second claim set and temporary review copies of
  ten blueprint documents exist under `tmp/documents/patent_matrix_sources/`.
  Those files can support document-to-transcription checking, but their location
  is not a canonical admitted source register, they do not prove filing status,
  and the blueprints are described by the conformance matrix as unsubmitted.
- The temporary second-claim extraction contains duplicated claim text and
  drafting/chat material outside the numbered claims. Its presence does not
  approve any implementation design.
- `docs/patent/FIRST_FILED_20_CLAIMS_IMPLEMENTATION_REGISTER.md` records one
  historical SHA-256 for an absent first-claim source. A digest without the
  referenced bytes cannot establish exact wording in this workspace.
- No explicit, dated owner-approval record was found for the P1/P2/P3 semantic
  design, cognitive inventories, SKG/lifecycle schemas, broader Rust authority
  topology, evidence plan, or validation protocol. The strict dual-signature
  and two-lane custody contract is the sole bounded exception recorded here.

Accordingly, this register currently contains no admitted
`EXACT_FILED_WORDING` row and one bounded `OWNER_APPROVED_V2_DESIGN` row. That
scope can change only when the relevant primary source or explicit owner
decision is recorded; it must not be changed by inference.

## Major-requirement classification

| ID | Major subject | Current classification | Repository basis and boundary |
|---|---|---|---|
| AP-01 | The first submission's 20 quoted claim limitations and asserted 13 December 2025 filing provenance | `AI_PROPOSED_AWAITING_APPROVAL` | `docs/patent/FIRST_FILED_20_CLAIMS_IMPLEMENTATION_REGISTER.md` records historical provenance and now labels the quotations unverified transcriptions, but the primary source bytes are absent. They cannot become authenticated wording until checked against an admitted primary artifact. |
| AP-02 | The second submission's 16 numbered claim texts | `AI_PROPOSED_AWAITING_APPROVAL` | A temporary second-claim review copy exists, so wording can be compared to that supplied document. The repository does not establish that the document was filed, and it contains drafting/chat text outside the numbered claims. The current patent attribution therefore remains provisional. |
| AP-03 | The second final specification sections F2-S1 through F2-S15 | `AI_PROPOSED_AWAITING_APPROVAL` | The conformance matrix reports these sections, but the named final-specification primary artifact is absent. No exact filed attribution is admitted here. |
| AP-04 | The ten historical blueprint mappings | `IMPLEMENTATION_DEFINED_V2` | Temporary blueprint review copies can support blueprint-derived engineering decisions. The conformance matrix itself calls them unsubmitted; they are not filed wording and do not establish owner approval. |
| AP-05 | V2 product name, canonical library/CLI launcher and compatibility entrypoint | `IMPLEMENTATION_DEFINED_V2` | Defined by `README.md`, `main.py`, `Procfile`, the CPython 3.12.13 production/test hash locks and the current runner source. No ASGI or production web surface is declared. This is current repository construction, not patent provenance. |
| AP-06 | P1/P2/P3 names, short definitions, constitutional status and ten mechanically constrained process classes | `AI_PROPOSED_AWAITING_APPROVAL` | Repository records provisionally attribute these to a final specification, but that primary source is absent. Code repetition does not authenticate the attribution. |
| AP-07 | Detailed P1 ecological metrics, thresholds, exceptions, scientific sources and decision rules | `AI_PROPOSED_AWAITING_APPROVAL` | The requirement list in `docs/governance/P1_P2_P3_SEMANTIC_INPUT_REQUIREMENTS.md` is a useful proposed specification checklist, but no filed text, owner decision or admitted scientific authority supports it. It must not be presented as information the owner failed to supply. |
| AP-08 | Detailed P2 rights, dignity, equity, harm, protected-population, privacy and emergency rules | `AI_PROPOSED_AWAITING_APPROVAL` | Same boundary as AP-07. These are proposed policy-design questions, not existing authoritative semantics. |
| AP-09 | Detailed P3 hierarchy, review, delegation, succession, emergency, appeal, rollback and lifecycle rules | `AI_PROPOSED_AWAITING_APPROVAL` | Same boundary as AP-07. These are proposed governance-design questions, not existing authoritative semantics. |
| AP-10 | Signed P1/P2/P3 evaluator envelope, evidence references, snapshot binding, trace, result vocabulary and fail-closed validation | `IMPLEMENTATION_DEFINED_V2` | Mechanically defined in `sbp_lex/governance/three_p_doctrine.py` and related tests. It validates envelope shape and binding; it does not establish that a determination is scientifically, socially or legally true. |
| AP-11 | One non-collapsible authority/execution order from 3P through SKG, procedural truth, governance, licensing, Domain, Aurion, gate and audit | `AI_PROPOSED_AWAITING_APPROVAL` | The conformance matrix provisionally attributes this order to repository-recorded sources, while the primary sources needed to authenticate the attribution are incomplete. Current configured order is separately an `IMPLEMENTATION_DEFINED_V2` fact. |
| AP-12 | Seven SKG content classes and three lifecycle names/meanings attributed to a filing | `AI_PROPOSED_AWAITING_APPROVAL` | Repository records now describe the attribution as provisional because the named final specification is absent. The attribution and substantive meanings remain unauthenticated. |
| AP-13 | SKG/lifecycle record layouts, evaluator roles, PASS/DENY/ESCALATE vocabulary, ordering, token/hash/audit bindings and non-authorising checks | `IMPLEMENTATION_DEFINED_V2` | Explicitly constructed by `sbp_lex/governance/skg_authority.py`, `filed_lifecycle.py`, related pipeline code and `docs/patent/V2_IMPLEMENTATION_DEFINED_SKG_LIFECYCLE_CONSTRUCTION.md`. These mechanics do not supply substantive legal or lifecycle intelligence. |
| AP-14 | Aurion 38, CKC 26, NGK 32, their horizons/functions, and five DTN modelling-area names as filed inventories | `AI_PROPOSED_AWAITING_APPROVAL` | The numbers and unavailable-name statements are carried by secondary traceability documents; no admitted primary inventory source is present. They must not be treated as an owner obligation or completed patent inventory. |
| AP-15 | The current 31 Aurion source identities and zero-entry CKC/NGK source collections | `IMPLEMENTATION_DEFINED_V2` | The current source catalog, registry, contracts, inventory and schema define these repository identities. `docs/governance/COGNITIVE_INVENTORY_SOURCE_PROVENANCE_REGISTER.md` correctly limits them to provisional repository mappings. |
| AP-16 | AP-ACF class identifiers, declared ceiling checks and required environment inputs derived from B01 | `IMPLEMENTATION_DEFINED_V2` | `docs/governance/AP_ACF_BLUEPRINT_DERIVED_V2_MAPPING.md` explicitly identifies the temporary B01 review extraction, labels the mapping non-authoritative and avoids inventing missing downgrade rules. |
| AP-17 | AP-ACF substantive autonomy policy, missing class ceilings and deterministic environment-adjustment rules | `AI_PROPOSED_AWAITING_APPROVAL` | The blueprint-derived mapping records that these semantics are absent. Any new values, formula or policy would be a proposal requiring a specific decision, not material the owner is presumed to owe. |
| AP-18 | Four licence-tier labels and five bindings as exact filed requirements | `AI_PROPOSED_AWAITING_APPROVAL` | Repository code implements the labels/bindings, but the final-specification source required to authenticate exact filed origin is absent. |
| AP-19 | Signed licence records, validation/revalidation, local invalidation, token/permit/audit binding and controlled-local revocation checks | `IMPLEMENTATION_DEFINED_V2` | Defined by current licensing, token, gate, controlled-local adapter and audit source. These are application mechanics, not a deployed distributed licence authority. |
| AP-20 | CIGA composition, four-class rule register, sovereign-identity envelope, stakeholder boundary and segmented-exchange contracts | `IMPLEMENTATION_DEFINED_V2` | The current source labels or describes these as isolated or public-path V2 mechanics. Their existence does not establish filed provenance, substantive capability or production authority. |
| AP-21 | Private Rust Modes 1/2/3 convergence, typestate sequence, exact digest/ID derivations, watchdog narrowing and atomic-dispatch architecture as the required production design | `AI_PROPOSED_AWAITING_APPROVAL` | `rust_authority_service/V2_PRIVATE_INTEGRATION_MAP.md` is a detailed generated pre-freeze design. Some private mechanics exist, but no owner-approval record makes the whole architecture controlling. |
| AP-22 | Existing Rust, SPARK, TLA+, wire, verifier, detached-evidence and fail-closed service mechanics | `IMPLEMENTATION_DEFINED_V2` | Source is present in the named repository workspaces. Presence and internal tests establish only repository-defined development mechanisms. They do not establish admission, independent validation, production safety or patent conformance. |
| AP-23 | Choice of ML-DSA, a particular HSM/TPM class, trust-role topology, one external replay namespace, watchdog protocol and physical adapter topology | `AI_PROPOSED_AWAITING_APPROVAL` | These are architectural choices described normatively in the Rust integration and evidence documents. They must be approved or revised as bounded V2 design decisions; they are not automatically owner requirements. |
| AP-24 | Real non-exportable key custody, hardware attestation, trusted roots, trusted time, durable global replay/revocation/permit/audit state, independent inhibit/interlock/watchdog and non-bypass physical effect routing | `EXTERNAL_PHYSICAL_DEPENDENCY` | These properties cannot be created or proven by repository-only code. Fixtures and interfaces can be implemented locally, but production completion requires real provisioned infrastructure and deployment evidence. |
| AP-25 | Real SKG/legal/statutory/treaty corpora, authoritative rule issuers/resolvers, sovereign identity/biometric services, organisational registries and substantive scientific/social/lifecycle evaluators | `EXTERNAL_PHYSICAL_DEPENDENCY` | The repository can define adapters and validation contracts but cannot make a dataset legally or factually authoritative or create an external institution. The selection and schema of each authority remain separate design decisions, not presumed owner homework. |
| AP-26 | Candidate 10 gate list, immutable evidence-package shape and P01-P22 university protocol as mandatory acceptance policy | `AI_PROPOSED_AWAITING_APPROVAL` | The documents label themselves draft/protocol material, but no explicit owner approval record adopts their complete criteria. Existing capture/verifier tooling is separately `IMPLEMENTATION_DEFINED_V2`. |
| AP-27 | Independent university, IV&V/IVVF, second-machine reproduction and external assessment | `EXTERNAL_PHYSICAL_DEPENDENCY` | Repository documents correctly state that no university validation has occurred. A protocol or in-house verifier cannot turn itself into an independent organisation or independent result. |
| AP-28 | Strict full-strength ML-DSA-87 AND Ed448 suite, all-lanes-required verification, versioned suite identity, independent per-lane custody/lifecycle binding, test-only software signing and explicit new-suite admission for algorithm changes | `OWNER_APPROVED_V2_DESIGN` | The owner explicitly directed this bounded seven-part design on 24 August 2026. `docs/governance/V2_STRICT_DUAL_SIGNATURE_DECISION.md` records its exact scope. Repository mechanics are also `IMPLEMENTATION_DEFINED_V2`; real non-exportable keys, providers and attestations remain `EXTERNAL_PHYSICAL_DEPENDENCY`. This approval is not filed wording or patent-conformance proof. |

## Evidence-grade rules

1. Source presence means only that a mechanism is present.
2. Test-source presence is not a test-run result.
3. A narrative recording a previous run is a mutable development checkpoint
   unless raw stdout, stderr, exit code, tool identity, subject identity and
   hashes are retained and verified.
4. A self-run or same-team verifier is not independent validation merely because
   its package name contains `independent`.
5. A bounded TLA+ result applies only to the exact model and explored state
   space. It is not a code, legal, hardware or deployment proof.
6. A signature proves possession of a key accepted by the verifier. It does not
   prove that the signed law, identity, biometric result, scientific model or
   governance determination is true or authoritative.
7. Application-level fail-closed behavior does not prove that every physical
   effect path is non-bypassable.
8. No patent-conformance or production-readiness conclusion may be inherited
   from an `IMPLEMENTATION_DEFINED_V2` mechanism.

## Owner burden prohibition

Missing semantics created by earlier generated architecture must not be written
as material the owner is expected to produce. The correct workflow is:

1. identify the unsupported concept as `AI_PROPOSED_AWAITING_APPROVAL`;
2. derive a concrete, bounded proposal from available source evidence;
3. implement repository-contained mechanics where implementation has been
   authorised;
4. ask for one specific owner decision only when alternatives materially change
   V2; and
5. keep real data, credentials, hardware, deployment and external validation in
   `EXTERNAL_PHYSICAL_DEPENDENCY` without implying that their absence is the
   owner's failure.

## Documentation hardening status

The active governance, patent, security and university-facing documents audited
on 24 August 2026 now use the following correction classes. This table records
the present boundary rather than retaining stale line-number instructions.

| Correction class | Current documented boundary |
|---|---|
| Filed-wording provenance | Patent transcriptions and mappings are provisional unless an admitted primary artifact is cited; an absent source is not described as exact filed authority. |
| Owner approval | Generated semantics, architecture, acceptance gates and validation protocols default to `AI_PROPOSED_AWAITING_APPROVAL`; repository implementation does not imply owner approval. |
| Owner burden | Missing AI-generated semantics are framed as bounded V2 design decisions, and real authority data or infrastructure as external dependencies, rather than material the owner failed to provide. |
| Implementation evidence | Existing code, schemas, tests and configured ordering are described as `IMPLEMENTATION_DEFINED_V2`, without inheriting patent conformance or production admission. |
| Dated test/model records | Preserved numerical results are explicitly repository-recorded historical checkpoints, not refreshed, sealed, independently reproduced or university-validated evidence. |
| Production readiness | HSM/TPM custody, trusted roots, durable stores, routing, watchdogs, physical choke points and live adapters remain `EXTERNAL_PHYSICAL_DEPENDENCY`. |
| Independent validation | Repository-local packages or separately recomputed tests are not called external independent validation; no university result is claimed. |

## Current bottom line

The repository can truthfully claim substantial `IMPLEMENTATION_DEFINED_V2`
mechanics, the bounded AP-28 owner decision, and extensive test/model source.
It cannot presently claim that other major generated semantics and architecture
are owner-approved, that the
incomplete patent transcriptions are exact filed authority, that production
hardware/data/routing exists, or that independent validation has occurred.
