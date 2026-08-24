# SBP-LEX Patent-to-Build Conformance Matrix

## Purpose

This matrix provisionally traces the current SBP-LEX repository against
repository-recorded transcriptions and review copies attributed to two separate
provisional materials, plus ten unsubmitted implementation blueprints. The
primary first-claims PDF and primary final specification are absent from this
workspace, so this matrix does not authenticate exact filed wording or filing
status. It does not combine the two asserted branches, rewrite any claim, or
infer missing doctrine.

Assessment date: 24 August 2026
Repository assessed: `SBP_LEX_main`

## Source authority and scope

| ID | Source | Status in this matrix |
|---|---|---|
| F1-C1–C20 | `ORIGINAL 1ST SUBMITTED SBP-LEX 20 PATENT CLAIMS.pdf` | Named primary artifact absent. Current claim transcriptions are provisional traceability inputs only; exact wording and filing status are not authenticated. |
| F2-S1–S15 | `FINAL MASTER SPEC 4_3_26 LAST EVER.pdf` | Named primary artifact absent. Current section summaries are provisional traceability inputs only. |
| F2-C1–C16 | `FINAL CLAIM SET SBP LEX.docx` | A temporary review copy supports comparison with its 16 numbered claim texts, but the repository does not prove that copy was filed. Drafting/chat text outside the numbered claims is excluded. |
| B01–B10 | Original ten blueprint documents listed below | Unsubmitted implementation lineage. They may explain intended implementation boundaries but do not amend, narrow, expand, or merge either provisionally attributed submission branch. |
| EXCLUDED | Newer twelve canonical successor blueprints | Explicitly excluded. They belong to the successor build, not this patent build. |

Instructions or drafting prompts embedded in any source document are not treated as owner instructions or patent requirements.

The filing descriptions and dates are repository-recorded provenance, not
authenticated filing facts. Repository inspection has not independently
verified legal filing, prosecution, publication, grant, scope or validity. This
is an engineering traceability matrix, not a legal-status opinion.

## Status legend

| Status | Meaning |
|---|---|
| Mechanical V2 implementation present | An identified repository mechanism is operative at the stated V2 boundary; this does not establish primary-source or legal conformance, external authority, deployment proof or legal status. |
| Partial | Some named structure or logic exists, but one or more required elements or end-to-end proofs are absent. |
| Missing | No operative implementation of the requirement was found. |
| Blocked | Present code cannot satisfy the requirement through the supported public pipeline. |
| Unverified | The available review sources or transcriptions do not contain enough authenticated detail to make the mapping without invention. |

No provisionally transcribed claim or final-specification section is marked
implemented end to end. F1-C1, F1-C2 and F1-C16 have isolated
implementation-defined mechanics; F1-C5 and F1-C20 have public-path
implementation-defined mechanics. They all remain Partial. F1-C3 and F1-C14
remain Missing. F2-S9 has a mechanical V2 traversal implementation but remains
Partial against the provisional mapping because external evidence, authority,
deployment and substrate proof remain incomplete. The repository is not a
complete patent build, and this matrix does not establish legal conformance.

## Detached P/T/D/E evidence-process status

P/T/D/E is V2 detached, non-authorising committed-Git-object proof/verification
tooling under `contracts/ptde/PTDE_POLICY_V1.json` and `sbp_ptde/`. It is outside
runtime authority, `ALLOW`, licence and effect semantics, but is part of the
handover evidence process. It is distinct from PTODF. No completed P/T/D/E
campaign or admitted P/T/D/E commit chain is claimed in this matrix.

## Provisional architecture interpretation

The current repository and generated traceability material use this configured
authority and execution order. The order is an
`IMPLEMENTATION_DEFINED_V2` fact where source implements it; its attribution to
provisionally attributed submission material is `AI_PROPOSED_AWAITING_APPROVAL` until primary sources are
admitted:

`3P constitutional constraint -> SKG authority substrate -> procedural truth and evidentiary sufficiency -> authority/governance traversal -> classification/licensing/autonomy controls -> Domain admissibility -> Aurion bounded pathway resolution -> execution gate -> audit`

The following are provisional V2 traceability rules, not authenticated filed
meanings or blanket owner-approved architecture:

1. Current V2 contracts treat P1, P2 and P3 as upstream prerequisites. Their
   substantive names, definitions and constitutional attribution remain
   `AI_PROPOSED_AWAITING_APPROVAL`.
2. Current V2 contracts place SKG upstream of downstream resolution. The
   substantive SKG/DTN meanings and their alleged filed provenance remain
   `AI_PROPOSED_AWAITING_APPROVAL`.
3. Domain is the pathway-space constrainer: it removes inadmissible candidates before Aurion.
4. Aurion is the bounded pathway resolver inside the already constrained space. It is non-executive, cannot elevate authority, cannot grant execution and cannot run before Domain.
5. The execution gate alone determines whether a resolved pathway remains mechanically inoperative or may reach an execution substrate.
6. The repository-reported 38 Aurion, 26 CKC and 32 NGK inventories remain
   separate and `SOURCE_UNAVAILABLE`; only the 31 evidenced Aurion identities
   are `PROVISIONAL_CURRENT`. Overlapping names or functions are not merged.
7. The two provisionally attributed submission branches remain separate
   traceability branches. Shared subject matter is cross-referenced, not
   legally merged or silently eliminated.

## Current-build evidence anchors

Governance-integrity integration is still changing. This correction therefore
does not refresh a final active traversal, line-range inventory, engine count or
test total. Source paths below are mechanical V2 evidence anchors; dated counts
or exact traversal observations must be freshly repinned before use as
current evidence.

| Anchor | Current evidence | Conformance consequence |
|---|---|---|
| E01 | `main.py`; `sbp_lex/pipeline/runner.py`; `sbp_lex/config/pipeline_config.py` | These are the public entry, single-pipeline runner and configured-order sources. This correction does not assert a refreshed final traversal while governance-integrity integration is changing. |
| E02 | `sbp_lex/governance/three_p_doctrine.py`; `sbp_lex/governance/three_p_policy_v2.py`; `tests/test_three_p_policy_v2.py`; `docs/THREE_P_IMPLEMENTATION_DEFINED_V2.md` | Exact P1/P2/P3 names and the existing signed fail-closed evaluator boundary are recorded. A content-neutral policy interpreter now requires versioned rules, thresholds, evidence authorities, lifecycle/revocation and fixtures and is labelled `AI_PROPOSED_AWAITING_APPROVAL`. It supplies no substantive PSE/PIE/PSGC policy or authority. |
| E03 | `sbp_lex/shared/state_builder.py`; `tests/test_state_builder_input_binding.py` | Canonical state preserves AP-ACF inputs plus the repository-configured licence tier, identity, jurisdiction, authority state, execution rights and autonomy inputs without caller-object aliasing. This does not authenticate filed provenance. |
| E04 | `sbp_lex/classification/router.py`; `tests/test_ap_acf_blueprint_profile.py`; `docs/governance/AP_ACF_BLUEPRINT_DERIVED_V2_MAPPING.md` | Blueprint-derived `IMPLEMENTATION_DEFINED_V2` mechanics close the class/subclass vocabulary, enforce B01's exact Class-5 example ceilings, enforce declared ceilings and require the three stated classification dimensions plus the three named environment modifiers. No Class 1-4 numeric ceilings or deterministic environmental downgrade formula are inferred; the mapping is `AI_PROPOSED_AWAITING_APPROVAL`, not filed or authoritative policy. |
| E05 | `sbp_lex/licensing/filed_licensing.py`; `sbp_lex/licensing/router.py`; `tests/test_four_tier_licensing.py` | Licensing admits only the four repository-configured tier labels and requires signed identity, jurisdiction, authority-state, execution-right and autonomy bindings. It rejects unknown/case-variant tiers, unsigned/untrusted evidence, live-binding mismatch, unlicensed actions and monotonic revocation rollback. Tier labels do not derive privileges, and their filed attribution is unverified. |
| E06 | `sbp_lex/domains/runner.py:10-55` | Active Domain Wrap contains four ordered checks: legal, sovereign, operational and risk. |
| E07 | `contracts/v2/cognitive-engine-inventory.schema.json`; `sbp_lex/aurion15/core/inventory.py`; `sbp_lex/aurion15/core/catalog.py`; `docs/governance/COGNITIVE_INVENTORY_SOURCE_PROVENANCE_REGISTER.md`; `tests/test_cognitive_inventory_schema.py`; `tests/test_aurion_inventory_identity.py`; `tests/test_cognitive_layer_separation.py`; `tests/test_engine_graph_runtime.py` | The exact current 31 class names, modules, classes, stages and dependencies are locked as `PROVISIONAL_CURRENT`. Two aliases and six external dependencies are non-counting; legacy, duplicate, reordered, unknown, case-variant and cross-layer inflation is rejected. CKC and NGK remain separate with zero admitted names, and DTN cannot substitute for a cognitive layer. The repository-reported 38/26/32/5 counts are `SOURCE_UNAVAILABLE`, not owner-approved or authoritative. |
| E08 | `sbp_lex/execution/execution_gate.py:158-248` | Application-level gate checks 3P and requires effect-authority token verification. No substrate executor or physical/deployment non-bypass proof is present. |
| E09 | `sbp_lex/security/signature_provider.py:30-52`; `tests/test_signature_provider.py:68-116` | Included software signing provider authenticates tokens but explicitly has no execution effect authority. |
| E10 | `sbp_lex/governance/engine.py:35-94` | Active governance requires explicit policy and upstream prerequisites; it is not a complete machine-readable constitutional/statutory/treaty authority system. |
| E11 | `sbp_lex/legacy_admission/contracts.py:91-124,125-177,180-203`; `tests/test_legacy_admission.py:59-72` | All 45 legacy artifacts start shadow-only, normal writes are empty, two non-importable sources are quarantined and no legacy engine can grant allow. Candidate promotion labels are not authority. |
| E12 | `sbp_lex/pipeline/runner.py:192-231`; `sbp_lex/audit` | Canonical hashes, an audit record, a ledger and legacy digests exist, but complete cryptographic attribution and composite live-state verification are not established. |
| E13 | `sbp_lex/governance/filed_frameworks.py`; `sbp_lex/pipeline/runner.py`; `sbp_lex/execution/execution_gate.py`; `tests/test_filed_frameworks.py` | PTODF executes immediately after procedural truth and before classification/licensing. AJ-SAAF executes before the base Governance determination; GALA and ABEGF execute after that determination but before Governance completion, GRC, Domain and Aurion. Each component has a separate signed evidence contract, exact pre/post 3P boundaries, chronological hash/token/audit binding, no independent execution authority, and fail-closed missing/invalid/order enforcement. These are implementation facts; filed provenance for the names and meanings is unverified. |
| E14 | `sbp_lex/security/token_stack.py`; `sbp_lex/execution/controlled_local_adapter.py`; `sbp_lex/audit`; `tests/test_controlled_local_adapter.py` | Every issued token binds the applicable signed licence record, exact tier, five-binding digest and revocation sequence. The execution gate and controlled local adapter revalidate the licence; the permit binds a fresh point-of-use licence source, and revocation between permit mint and dispatch prevents handler invocation. Permit, receipt and terminal audit bind the licence evidence. This implements the current V2 controlled-local interface; it does not establish a deployed distributed revocation network. |
| E15 | `sbp_lex/baseline/request_controls.py`; `sbp_lex/pipeline/runner.py`; `sbp_lex/security/token_stack.py`; `sbp_lex/execution/execution_gate.py`; `sbp_lex/execution/controlled_local_adapter.py`; `sbp_lex/audit`; `tests/test_foundational_public_pipeline.py` | Sovereign identity and the authority boundary now traverse the public foundational request path and are bound into the state/hash, token, gate, controlled-local permit/receipt and audit evidence paths. They remain non-authorising and depend on external production issuers, authorities, custody and durable trust state. Test-source presence is not a refreshed run claim. |
| E16 | `sbp_lex/composition/ciga_composition.py`; `tests/test_ciga_composition.py`; `sbp_lex/rules/rule_artifact_register.py`; `tests/test_rule_artifact_register.py` | Claim 1 has an isolated signed composition-only contract for its four capability classes. Claim 2 has an isolated signed four-class rule-artifact register that escalates unresolved conflicts and performs no legal interpretation. Neither contract is in the public pipeline, grants authority, or proves the described substantive capability. |

## Provisional first-submission mapping — 20 broad claim transcriptions

| Claim | Provisional requirement transcription | Status | Current evidence | Open implementation or external dependency |
|---|---|---|---|---|
| F1-C1 | Unified legal computation, simulation, identity and sovereign decision architecture | Partial — isolated mechanical V2 composition contract present | E01, E07, E10 and E15 show a combined pipeline, several modelling engines and a mechanical sovereign-identity admission boundary. E16 adds isolated signed composition-only evidence for four repository-configured capability classes, but it is not public-path integration or substantive CIGA proof. | A bounded V2 design decision is required before integrating the composition contract. Real identity, legal, simulation and decision authorities remain external physical dependencies. |
| F1-C2 | Multi-layer constitutional, statutory, regulatory and treaty rules | Partial — isolated mechanical V2 rule register present | E16 provides an isolated signed register for four repository-configured rule classes with provenance and conflict escalation. Root, governance and precedence components exist, but no authentic rule corpus or authoritative resolver is integrated. | A bounded V2 design decision is required before integrating the rule register. Authentic rule corpora, precedence sources and conflict authorities remain external physical dependencies. |
| F1-C3 | Convert legislation, case law and regulation into machine-readable governance | Missing | No ingestion, normalization, provenance or authoritative rule-compilation subsystem was found. | A source-to-artifact conversion and provenance design remains `AI_PROPOSED_AWAITING_APPROVAL`; authentic legal sources and interpretation authority are external dependencies. |
| F1-C4 | Autonomous compliance forecasting and prevention | Partial | Policy simulation and predictive-risk engines exist in E07, but no complete compliance forecasting/prevention loop is active. | Define sourced compliance facts, deterministic forecast contracts and governed preventive actions. |
| F1-C5 | Sovereign identity using biometrics, cryptographic verification and multi-jurisdiction access | Partial — mechanical V2 public-path integration present | E15 places the signed sovereign-identity admission contract in the public foundational request path and binds it through later state/hash, token, gate, controlled-local effect and audit evidence. It grants no authority/licence/execution/effect rights and deliberately does not treat the biometric reference digest as biometric proof. No production identity issuer, biometric verifier, privacy deployment, hardware custody or durable revocation authority is established. | Admit and independently validate real identity/biometric authorities, privacy controls, custody and durable revocation while preserving the non-authorising boundary. |
| F1-C6 | Unified environmental, economic, infrastructure, demographic and emergency simulation | Partial | E07 contains ecological, economic, infrastructure, demographic and crisis-related engines; no unified DTN substrate exists. | Implement the DTN contract, reproducible scenario state and cross-domain integration. |
| F1-C7 | Unified governance among agencies, corporations, utilities and treaty bodies | Partial | Authority and policy fields exist; no multi-organization governance/federation layer is implemented. | Add attributable organizational roles, mandates, precedence and cross-body traversal. |
| F1-C8 | Digital-twin prediction of structural, supply-chain, environmental and cyber-physical failure | Partial | Infrastructure, interdependency, ecological and cascading-failure engines exist; the specified digital twin is inactive and incomplete. | Implement an identified, reproducible DTN with all four failure domains. |
| F1-C9 | National carbon, biodiversity, atmospheric and ecological modelling | Partial | One ecological constraint engine exists. National carbon, biodiversity and atmospheric models are absent. | Add source-bound domain models and validation fixtures for each named field. |
| F1-C10 | Crisis response, multi-agency coordination and scenario planning | Partial | Crisis-recognition and strategic-risk logic exists; multi-agency coordination and governed scenario planning do not. | Implement authority-routed crisis scenarios and coordination state. |
| F1-C11 | Cross-border agreement and compliance harmonisation | Partial | Jurisdiction and conflict components exist, mostly caller-supplied or shadow-only. No treaty/agreement harmonisation engine is active. | Implement SKG treaty mandates, cross-border precedence and harmonisation tests. |
| F1-C12 | Dynamic national risk matrices for economic, environmental, health and security conditions | Partial | Economic, ecological, predictive-risk and security engines exist. A national matrix and health domain are absent. | Define the complete deterministic risk-matrix schema, sources and update contract. |
| F1-C13 | Human-rights, equity and harm-prevention constraints | Partial | Ethical and societal-stability engines exist, but explicit rights/equity authority mappings are absent. | Encode sourced rights obligations and non-overridable harm constraints in SKG/3P traversal. |
| F1-C14 | Intergenerational and future-harm modelling | Missing | CKC and NGK have zero admitted identities; no authenticated primary-source long-horizon model is available. | CKC/NGK structure and semantics remain `SOURCE_UNAVAILABLE`; any generated contracts are proposals pending a bounded design-authority decision. |
| F1-C15 | Pre-adoption socioeconomic and infrastructure policy-impact modelling | Partial | Policy simulation, economic and infrastructure engines exist without a unified verified impact model. | Bind policy scenarios to DTN evidence, authority and reproducible outputs. |
| F1-C16 | Cryptographically segmented cross-department and cross-jurisdiction data exchange | Partial | An isolated implementation-defined V2 exchange contract now uses real AES-256-GCM independently per segment, signed whole-envelope authority, exact sender/recipient/jurisdiction/policy/request bindings, monotonic revocation, audit digests and replay/order/tamper rejection. Transport, durable key custody, production policy authorities and distributed enforcement remain explicitly external and unproven. | Traversal position is a bounded V2 design decision. Production key custody, policy/revocation authorities, transport and distributed enforcement remain external dependencies. |
| F1-C17 | Modular health, transport, energy, finance, environment, defence and emergency engines | Partial | Environment, economic/security and crisis-related engines exist. The authenticated primary-source sector inventory is unavailable. | A one-to-one sector-engine design remains provisional pending primary-source admission or an explicit bounded V2 decision. |
| F1-C18 | National infrastructure investment allocation for resilience, emissions and public benefit | Partial | A resource-allocation engine exists, but it is not the complete described investment-allocation system. | Authority-bound objectives and allocation mechanics are design proposals; authentic evidence and investment authority are external dependencies. |
| F1-C19 | Automated regulatory actions triggered by thresholds, violations or harms | Partial | Thresholds, governance results and an execution gate exist. An admitted regulatory-action authority and substrate effect path do not. | Bind triggers to SKG authority, licensing, effect authority, revocation and audit. |
| F1-C20 | Unified interface for government, regulators, corporations, NGOs and treaty bodies under authority boundaries | Partial — mechanical V2 public-path integration present | E15 places the signed authority-boundary contract in the public foundational request path and binds it through later state/hash, token, gate, controlled-local effect and audit evidence. The five stakeholder labels grant no rights and cannot grant authority/licence/execution/effect permission or bypass. No production mandate issuer, organizational registry/policy, transport/UI, custody or durable trust state is established. | Admit and independently validate real stakeholder identity, mandate, registry, role-policy, session and deployed enforcement evidence without allowing interface labels to create authority. |

## Provisionally attributed second-submission review copy — 16 claims

| Claim | Provisional requirement transcription | Status | Current evidence | Open implementation or external dependency |
|---|---|---|---|---|
| F2-C1 | Authority-first system with dynamic jurisdiction, an external superior gate, procedural validation and conflict resolution; independent of model internals and non-bypassable without architecture change | Partial | E01, E08 and E10 provide application structure. Dynamic jurisdiction and substrate-level superiority/non-bypass are not implemented. | Activate authoritative jurisdiction resolution and implement/prove the external substrate enforcement boundary. |
| F2-C2 | Runtime jurisdiction determination with continuous re-evaluation on operational-context change | Missing | Jurisdiction is normally caller-supplied; the legacy determination engine is shadow-only. 3P is re-evaluated, but jurisdiction itself is not continuously resolved. | Define jurisdiction evidence, change triggers, deterministic recalculation and safe-state tests. |
| F2-C3 | Gate enforces authority without accessing, retraining, modifying, disabling or reconfiguring the governed system | Partial | The Python gate is separate from model internals. There is no governed-system adapter/substrate proof establishing the whole negative limitation. | Implement a separate enforcement adapter and bypass-focused deployment evidence. |
| F2-C4 | Hierarchical constitutional, statutory, regulatory, treaty, delegated and institutional authority precedence | Partial | Some precedence and authority-chain code exists, but the complete hierarchy is not active in SKG. | Encode all six authority classes and deterministic conflict precedence. |
| F2-C5 | Escalation to judicial, sovereign, regulatory or treaty authority | Partial | GRC/escalation states exist; the four transcribed authority destinations and attributable routing are not complete. | Destination-specific records and routing are proposed V2 design work; real destination authorities remain external. |
| F2-C6 | Procedural validation of jurisdiction, licence, evidence and statutory compliance | Partial | E03, E05 and E14 establish signed licence validation and preserved inputs; jurisdiction authority and statutory compliance remain incomplete. | Authentic jurisdiction and statutory sources remain external; any additional validation mechanics require a bounded V2 design decision. |
| F2-C7 | Runtime authority instantiation, suspension, modification and revocation without modifying the governed AI | Missing | Revocation-related legacy functions are shadow-only; no complete admitted authority lifecycle exists. | Implement signed authority lifecycle events and substrate enforcement independent of model modification. |
| F2-C8 | Cryptographically attributable, tamper-detectable audit records binding authority basis and validation state | Partial | E12 provides deterministic hashing and audit records; the audit record is not itself proven attributable by an admitted authority signature and composite verification remains incomplete. | Sign/finalize the audit envelope and verify record, ledger, live chain, authority basis and validation state together. |
| F2-C9 | Offline, online and hybrid deployment while preserving authority-validation integrity | Missing | No explicit three-mode deployment architecture or equivalence evidence was found. | Define deployment profiles, trust-anchor handling, revocation freshness and parity tests for all three modes. |
| F2-C10 | Execution authorization independent of probabilistic confidence, statistical scoring and model-derived scoring | Partial | Core decisions are rule-gated, but current active engines consume numeric risk/score fields; no proof distinguishes evidence facts from prohibited decision authority. | Define the permitted evidence boundary and prove scores can never independently authorize execution. |
| F2-C11 | Method form of claim 1 | Partial | Same evidence and gaps as F2-C1. | Prove the complete ordered method traversal and non-bypass failure cases. |
| F2-C12 | Method form of dynamic jurisdiction re-evaluation | Missing | Same gap as F2-C2. | Implement and test context-change re-evaluation before any later stage continues. |
| F2-C13 | Method form of runtime authority lifecycle | Missing | Same gap as F2-C7. | Implement and test instantiation, suspension, modification and revocation events. |
| F2-C14 | Method form of cryptographic audit | Partial | Same evidence and gaps as F2-C8. | Add the complete signed, tamper-detecting audit method and verifier. |
| F2-C15 | Apparatus/system form of the authority-first architecture | Partial | Software modules exist, but the claimed external superior apparatus/substrate boundary is not demonstrated. | Define and evidence the actual enforcement apparatus and interface. |
| F2-C16 | Computer-readable-medium form | Partial | Source code exists, but the underlying claim limitations remain incomplete. | Treat this as satisfied only when the referenced method/system limitations pass end-to-end tests. |

## Provisional second-submission final-specification mapping

| Section | Provisional section summary | Status | Current evidence | Open implementation or external dependency |
|---|---|---|---|---|
| F2-S1–S2 | Structurally external, hierarchically superior sovereign execution constraint; not a model, analytics platform or optimizer | Partial | Pipeline/gate separation exists at application level. Substrate superiority is declared, not implemented or demonstrated. | Establish the external enforcement boundary and keep modelling engines non-authoritative. |
| F2-S3.1 | P1 PSE, P2 PIE and P3 PSGC; all ten listed downstream process classes mechanically constrained by the 3P Core | Partial | E02 records repository-configured names and repeated fail-closed checks. The primary final specification is absent, so the wording and substantive meanings are unverified. The policy interpreter is content-neutral and `AI_PROPOSED_AWAITING_APPROVAL`. | Substantive P1/P2/P3 policy requires a bounded V2 design-authority decision; genuine evidence sources and evaluators remain external dependencies. |
| F2-S3.2 | Authority precedes behaviour; legitimacy precedes execution; procedural truth and evidentiary sufficiency precede release | Partial | E01 orders the main stages correctly. Procedural truth accepts simplified caller facts and lacks full evidentiary traversal proof. | Implement source provenance, evidentiary sufficiency and mandatory negative traversal tests. |
| F2-S4 | Absolute substrate-level irreversibility, persistent inoperability and resistance to model, parameter, training-data and vendor alteration | Missing | E08 is an application-level function. No substrate executor or bypass proof exists. | Implement the substrate enforcement layer and adversarially prove every named bypass path remains inoperative. |
| F2-S5 | Authority-first operation above heterogeneous AI, independent of model internals and probabilistic outputs, across sovereign domains | Partial | External pipeline shape exists; authority/jurisdiction are largely caller-provided and score-bearing engines remain in the active graph. | Authenticate authority sources, separate evidence from authorization and test heterogeneous adapters. |
| F2-S6 | SKG constitutional authority substrate with seven named content classes and downstream non-override | Partial | An active implementation-defined V2 SKG envelope requires signed evidence for seven repository-configured content classes after Root and before procedural truth, binds the result into tokens/gate/effect/audit, and creates no authority or execution grant. The primary provenance, substantive rule model and resolver are absent. | The seven-class attribution and substantive SKG semantics are `AI_PROPOSED_AWAITING_APPROVAL`; authentic rule corpora, issuers and resolvers are external dependencies. |
| F2-S7 | Deterministic DTN under SKG, procedural truth and 3P across five named modelling areas | Missing | The DTN legacy function is shadow-only; individual signal engines do not form the specified substrate, and the five repository-reported modelling-area names are `SOURCE_UNAVAILABLE`. | DTN names and semantics require primary-source admission or a bounded V2 design decision; authoritative data/models remain external dependencies. |
| F2-S8.1 | Aurion-15: repository-reported 38 engines; present-day, non-executive, procedurally bound, no authority elevation | Partial | E07 source-locks the exact current 31 as `PROVISIONAL_CURRENT` and prevents aliases, six external dependencies and legacy artifacts from inflating the count. The reported remaining seven names are `SOURCE_UNAVAILABLE`. | Extend the inventory only after primary-source admission or a bounded V2 design decision; do not invent or substitute names. |
| F2-S8.2 | CKC: repository-reported 26 engines, 25–150-year horizon and four long-horizon functions | Missing | E07 records zero admitted CKC names; the reported inventory, function names and semantics are `SOURCE_UNAVAILABLE`. | Any CKC inventory or semantics require primary-source admission or a bounded V2 design decision; generated placeholders do not count. |
| F2-S8.3 | NGK: repository-reported 32 engines, 50–500-year horizon and conditional tags/classification | Missing | E07 records zero admitted NGK names; the reported inventory and tag/classification vocabulary are `SOURCE_UNAVAILABLE`. | Any NGK inventory or semantics require primary-source admission or a bounded V2 design decision; generated placeholders do not count. |
| F2-S9 | Mandatory traversal through AJ-SAAF, PTODF, GALA and ABEGF | Partial — mechanical V2 traversal present | E13 identifies four distinct active contracts in the V2 mechanical placement. Any component failure invalidates licence state; no framework independently grants Governance `ALLOW`, execution approval or effect authority. Filed provenance for the names/meanings is unverified, and production providers/substrate proof are absent. | Retain and freshly validate the implementation facts at a pinned revision; treat the complete architecture as `AI_PROPOSED_AWAITING_APPROVAL` pending primary-source admission or a bounded V2 decision. External independent validation remains a separate dependency. |
| F2-S10 | Four licence tiers and cryptographic binding to identity, jurisdiction, authority, execution rights and autonomy, with invalidation/revocation cascades | Partial | E03, E05 and E14 implement the exact four-tier signed mechanical contract, local invalidation cascade, token/gate/permit/audit bindings and final point-of-use revocation denial. No tier-to-right mapping is inferred. A genuinely distributed authoritative revocation deployment is not proven. | Connect every distributed execution substrate to one authoritative monotonic revocation source and add propagation/restart/partition fixtures before claiming primary-source or production conformance. |
| F2-S11 | No execution path outside governance; bypass produces substrate inoperability | Missing | Application gate checks are strong but can only govern callers that invoke this pipeline. | Implement a substrate choke point and evidence that every execution adapter is downstream of it. |
| F2-S12 | Structural non-alienation of authority routing, procedural truth, attestation, autonomy ceilings, licensing and substrate gating | Missing | Modules are separately importable/deployable; no composition attestation or deployment lock establishes inseparability. | Add startup/deployment composition verification and reject incomplete fragments. |
| F2-S13 | Five governance-integrity functions plus three named lifecycle engines, lawful continuity, non-coercion and 3P/SKG subordination | Partial | Three repository-configured lifecycle contracts are signed, non-authorising, mechanically 3P/SKG-bound and ordered by V2 source. Their filed attribution and substantive meanings are unverified. Substantive transition models and production evidence sources are absent. | Substantive lifecycle rules require a bounded V2 design decision; genuine evidence/model providers remain external dependencies. |
| F2-S14 | Root cryptographically binds identity, jurisdiction, authority, execution rights and autonomy; distributed revocation disables execution | Partial | E05 and E14 bind all five attributes at root and across the token/effect path, with controlled-local point-of-use revocation denial. The included production software signer still has no effect authority and distributed disablement is not deployed or proven. | Admit the selected hardware-backed effect-authority provider and prove revocation across every distributed substrate. |
| F2-S15 | Civilisational positioning: planetary stability, population integrity, lawful sovereign continuity and inability to function outside governance | Unverified | The declarations and partial controls exist; missing substantive 3P, SKG, licensing, lifecycle and substrate enforcement prevent mechanical demonstration. | Mark conformant only after the prerequisite sections pass composite end-to-end and bypass tests. |

## Original ten unsubmitted blueprints

Current review-source location:
`tmp/documents/patent_matrix_sources/`. This is a temporary, non-canonical
review area, not an admitted filing-source or owner-approval register.

| ID | Blueprint | Controlling implementation contribution | Current status |
|---|---|---|---|
| B01 | `Australia and Pacific Autonomy Classification Framework.docx` | Five classes, subclasses 4A/4B/5A/5B, autonomy ceilings, environment modifiers, declaration and licensing/gating relationship | Partial: E03 now preserves public inputs and E05 binds signed autonomy, but class-specific ceiling semantics remain incomplete. |
| B02 | `CANONICAL MASTER BLUEPRINT SERIES.docx` | Index of ten intended canonical blueprint documents | Unverified: it is an index, not a complete requirement document; the current repo does not contain that exact ten-file canonical Markdown series. |
| B03 | `DOMAIN WRAP LAYER — V6 (FINAL BLUEPRINTandDEFINITION LOCK).docx` | Deterministic, non-authoritative multi-domain admissibility before Aurion, with bounded retry/fallback and immutable trace | Partial: E06 provides four ordered domains before Aurion; full contract, bounded retry evidence and immutable-domain-trace proof are incomplete. |
| B04 | `procedural truth output discipline engine.docx` | Procedural truth engine dependent on validation, sufficiency, corroboration and output discipline | Partial: those components exist, but the current procedural-truth proof relies on simplified caller facts. |
| B05 | `SKG_DTN_Domain_alignment.docx` | SKG/DTN as external intelligence/truth; Domain as internal enforcement converting verified truth into non-bypass constraints; Aurion selects within constrained space | Partial: the authenticated SKG mechanical envelope is active in the correct upstream position; its production rule corpus/resolver and the DTN substrate remain incomplete, and substrate non-bypass is absent. |
| B06 | `The Architectural Engineering Blueprint Document.docx` | Repository structure, canonical state, fixed pipeline, tokens, AP-ACF, thresholds, root, Domain, Aurion, gate, hashes and audit | Partial: the structural skeleton is recognizable, but E04, E07–E10 and the unauthenticated specification gaps prevent full conformance. |
| B07 | `Theoretical SBP-LEX V6 blueprint..docx` | External deterministic control plane, hard gate, state/root/governance/Domain/Aurion/gate/audit and 3P terminology | Partial: application control plane exists; external substrate enforcement and substantive 3P do not. |
| B08 | `token_stack.py V6 DEFINITION CANONICAL.docx` | Deterministic signed traversal tokens bound to request/state/stage/tier/corroboration, freshness and nonce | Partial: E14 adds complete repository-configured root/licence bindings to every token; a production effect-authority issuer remains absent. |
| B09 | `V6 definitional anti drift Blueprint.docx` | Terminology, execution order and non-bypass anti-drift locks | Partial: tests lock some contracts and order; complete patent inventory and deployment-boundary locks are absent. |
| B10 | `V6 Intergrational Architectural Blueprint.docx` | Fixed traversal and boundary contracts; external signals; AP-ACF, root, PT, classification, licensing, governance, GRC, Domain, Aurion, tokens, gate and audit | Partial: runner order broadly matches; class-specific AP-ACF ceiling/environment semantics, external SKG/DTN, distributed authoritative revocation/deployment and substrate enforcement remain incomplete. |

## Engine-inventory non-overlap register

| Layer | Repository-reported role | Repository-reported count | Authenticated complete naming list | Current admitted count | Decision |
|---|---|---:|---|---:|---|
| Aurion-15 | Present-day, procedurally bound, non-executive pathway resolution | 38 (`SOURCE_UNAVAILABLE`) | No — seven canonical names unavailable | 31 | E07 locks the current 31 as `PROVISIONAL_CURRENT`. Two aliases, six external dependencies and all legacy artifacts are non-counting. Do not declare the seven unavailable names. |
| CKC | 25–150-year civilisational modelling, non-executive | 26 (`SOURCE_UNAVAILABLE`) | No — all 26 names and four named function names unavailable | 0 | E07 admits zero names. Keep separate; any inventory is a proposal until primary-source admission or a bounded V2 decision. |
| NGK | 50–500-year species-scale foresight, conditionally tagged and non-executive | 32 (`SOURCE_UNAVAILABLE`) | No — all 32 names and conditional-tag/classification vocabulary unavailable | 0 | E07 admits zero names. Keep separate; any inventory is a proposal until primary-source admission or a bounded V2 decision. |

Name similarity is insufficient evidence of identity. A future crosswalk must compare, for every engine: canonical name, layer, time horizon, reads, outputs, authority role, execution position, dependencies, deterministic contract and tests. Only exact contract equivalence can justify one implementation serving more than one documented name, and shared implementation must not collapse the three structural layers.

## Critical conformance blockers

| Priority | Blocker | Provisional traceability impact | Completion evidence required |
|---:|---|---|---|
| 1 | No substantive authenticated P1/P2/P3 evaluators | The repository-configured 3P boundary is represented but cannot establish substantive PSE, PIE or PSGC satisfaction. | Real evidence contracts, provenance, negative fixtures and stage-by-stage subordination tests. |
| 2 | Mechanical input preservation and bounded blueprint mapping are present; substantive AP-ACF semantics remain incomplete | Canonical state preserves AP-ACF and repository-configured licence inputs. Current mechanics enforce the closed vocabulary, B01's Class-5 example ceilings, declared ceilings and required environment inputs, but Class 1-4 numeric ceilings and a deterministic environment-adjustment rule remain unavailable and are not inferred. | Any remaining semantic rules require a bounded V2 design-authority decision and retain `AI_PROPOSED_AWAITING_APPROVAL` until then; blueprint mechanics are not filed policy. |
| 3 | No substrate-level execution choke point | The strongest non-bypass, irreversibility and superiority limitations are unimplemented. | Separate executor/enforcement adapter and adversarial bypass evidence. |
| 4 | No admitted effect-authority provider | Included signing can authenticate records but cannot authorize execution under the gate's own requirement. | Admitted custody/provider contract and positive/negative cryptographic execution fixtures. |
| 5 | SKG mechanical authority admission is active; substantive SKG and DTN substrates remain incomplete | The seven-class authenticated SKG envelope and downstream non-override mechanics now traverse actively, but the authoritative rule corpus/resolver and deterministic DTN modelling claims remain unmet. | Real source-backed SKG rule/resolution fixtures plus the complete deterministic DTN under SKG, procedural truth and 3P, with non-override/reproducibility tests. |
| 6 | Cognitive source inventory mechanically locked; attributed inventories unresolved | E07 prevents count inflation and preserves layer separation, but seven Aurion names, all CKC/NGK names, CKC's four function names and NGK's vocabulary remain `SOURCE_UNAVAILABLE`. DTN's five modelling-area names are also unavailable. | Extend only after primary-source admission or a bounded V2 decision; placeholders and cross-layer substitution remain prohibited. |
| 7 | Mechanical V2 placement present; primary-source conformance unverified | E13 records early PTODF and Governance-internal AJ-SAAF, GALA and ABEGF mechanics, with no independent authority grant. This correction does not refresh a final traversal while governance-integrity integration is changing. | Repin and validate the implementation facts at an identified revision; primary-source admission, legal review and external independent validation are separate. |
| 8 | V2 controlled-local four-tier licence interface resolved; distributed revocation deployment remains open | E03, E05 and E14 now cover repository-configured tiers, five signed bindings, no inferred tier privilege, immediate local invalidation, token/gate/permit/audit binding and fresh point-of-use revocation denial. Distributed disablement is not deployed or proven. | Connect the same fail-closed monotonic revocation authority to every distributed substrate and prove propagation, restart and partition behavior. |
| 9 | Resolved at the exact mechanical-interface level; production lifecycle intelligence remains external | The authenticated seven-class SKG envelope now traverses after Root. Three repository-configured lifecycle components traverse after ABEGF, are signed and 3P/SKG-bound, preserve the configured continuity/non-coercion flags, cannot self-authorise or supersede Governance, and are bound through tokens, gate, controlled-local permits and audit. The deterministic order/evidence envelope is implementation-defined; no admitted primary source in this workspace authenticates those mechanics as filed. | Admit real SKG and lifecycle evidence/model providers and substantive transition fixtures before claiming production or substantive-intelligence conformance. |
| 10 | Broad-claim domain systems incomplete; Claims 5 and 20 have mechanical V2 public-path integration and Claim 16 remains isolated | Claim 5 sovereign-identity admission and Claim 20 authority-bounded stakeholder/request admission now traverse the public foundational request path and bind through later evidence boundaries. Claim 16 authenticated segmented exchange remains an isolated non-authorising mechanical contract. External identity issuers, biometric verification, organizational mandates/policies, durable key custody, transport and distributed enforcement remain unproven. | Independently validate Claims 5 and 20 against real production authorities and deployment evidence; separately approve and integrate Claim 16 only when its exact boundary is fixed; complete one-to-one claim fixtures for every remaining named sector, model, interface and governed action. |

## Legacy-engine admission rule retained

All 45 legacy artifacts remain `shadow_only` during initial admission. They may record observations and comparisons but must not mutate active state, grant `ALLOW`, or affect the active outcome. Security/invariant engines may become mandatory veto only after explicit contract tests and real-fixture comparison pass. Separate evidence engines may later become corroboration. Duplicated, ambiguous or unverified engines remain shadow-only. No promotion is currently evidenced.

## Conformance conclusion

The current repository is a provisionally mapped engineering skeleton, not a
fully conformed patent build. Its strongest implementation facts are the
ordered authority-first pipeline, signed fail-closed 3P boundary,
seven-class SKG envelope, root/token/hash structures, Domain-before-Aurion
placement, non-executive Aurion posture, four-framework traversal, three
non-authorising lifecycle contracts, four-tier V2 licensing interface,
controlled-local point-of-use revocation denial, application-level gate and
audit scaffolding. F1-C1 and F1-C2 also have isolated non-authorising mechanics,
while F1-C3 and F1-C14 remain Missing and no provisionally mapped claim is
complete end to end. The 31 current Aurion identities are
`PROVISIONAL_CURRENT`; the reported 38/26/32/5 inventories remain
`SOURCE_UNAVAILABLE`. Primary-source admission and legal review are required
before claiming patent alignment or exact filed provenance.

Current V2 source places Aurion after Domain constraints and before the
execution gate as a bounded non-executive pathway resolver. That placement is
`IMPLEMENTATION_DEFINED_V2`; its attribution to the absent primary final
specification remains `AI_PROPOSED_AWAITING_APPROVAL`.
