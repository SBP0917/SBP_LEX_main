# Cognitive Inventory Source and Provenance Register

Status: `IMPLEMENTATION_DEFINED_V2_SOURCE_INVENTORY`

This is a non-authorising repository-source register. It records only identities
that current source can evidence. It does not supply missing primary-source names,
establish legal filing status, activate a runtime component, grant authority, or
permit one cognitive or modelling layer to stand in for another.

## Admission rule

An engine identity is admitted only when all of the following repository facts
agree exactly:

1. its module is an entry in `sbp_lex/aurion15/core/catalog.py`;
2. importing that module registers the same canonical name, class, stage, and
   dependency tuple in the shared Aurion registry;
3. the canonical name has an explicit closed-world mutation contract in
   `sbp_lex/aurion15/core/contracts.py`; and
4. the same identity and metadata occur in
   `sbp_lex/aurion15/core/inventory.py`.

`tests/test_aurion_inventory_identity.py` mechanically checks that agreement.
The admission is `PROVISIONAL_CURRENT`: it records a current repository mapping,
not that the identity is one of the unavailable provisionally attributed canonical names.

Aliases, external dependencies, legacy/shadow functions, placeholders, similar
functions, and names belonging to another layer are never counting identities.
Neither functional resemblance nor a shared dependency establishes identity.

## Source/provenance boundaries

| Layer or substrate | Repository-recorded count; primary source status | Names admitted by current repository evidence | Unavailable identity material | Counting boundary |
|---|---:|---:|---|---|
| Aurion-15 | 38; `SOURCE_UNAVAILABLE` for primary-source verification | 31 | Seven canonical engine names | Only the 31 identities satisfying the admission rule count. Two aliases and six external dependencies are `NON_COUNTING`; legacy/shadow artifacts do not count. |
| CKC | 26; `SOURCE_UNAVAILABLE` for primary-source verification | 0 | All 26 canonical engine names and four named long-horizon function names | No placeholder, Aurion identity, NGK identity, DTN function, alias, dependency, or legacy artifact may count. |
| NGK | 32; `SOURCE_UNAVAILABLE` for primary-source verification | 0 | All 32 canonical engine names and the conditional-tag/classification vocabulary | No placeholder, Aurion identity, CKC identity, DTN function, alias, dependency, or legacy artifact may count. |
| DTN modelling areas | Five names reported; `SOURCE_UNAVAILABLE` for primary-source verification and for the names themselves | 0 | All five reported modelling-area names and their individual semantics | DTN is a modelling substrate, not an Aurion, CKC, or NGK layer. The legacy `digital_twin_network` function is not an authenticated primary-source modelling-area identity and counts toward none of the three engine inventories. |

The numeric mappings above are traceability statements carried by
`docs/patent/SBP_LEX_PATENT_TO_BUILD_CONFORMANCE_MATRIX.md` and
`docs/patent/FIRST_FILED_20_CLAIMS_IMPLEMENTATION_REGISTER.md`. Repository
inspection does not independently verify them against a primary source,
establish their legal status, or reconstruct the unavailable naming lists. This
register does not characterize them as owner-approved or authoritative.

## Admitted Aurion repository identities

The following names are copied from the exact current source-locked inventory;
they are not asserted to be the unavailable provisionally attributed names:

1. `procedural_validation_engine`
2. `authority_first_execution_engine`
3. `authority_resolution_engine`
4. `autonomy_boundary_engine`
5. `governance_compliance_engine`
6. `governance_routing_engine`
7. `legal_conflict_resolution_engine`
8. `legitimacy_verification_engine`
9. `policy_simulation_engine`
10. `cascading_failure_detection_engine`
11. `constraint_alignment_engine`
12. `crisis_recognition_engine`
13. `decision_integrity_engine`
14. `evidence_corroboration_engine`
15. `evidence_sufficiency_engine`
16. `information_integrity_engine`
17. `system_interdependency_engine`
18. `demographic_monitoring_engine`
19. `economic_signal_engine`
20. `ecological_constraint_engine`
21. `ethical_constraint_engine`
22. `infrastructure_state_engine`
23. `institutional_integrity_engine`
24. `operational_stability_engine`
25. `predictive_risk_engine`
26. `resource_allocation_engine`
27. `risk_detection_engine`
28. `security_state_engine`
29. `societal_stability_engine`
30. `strategic_conflict_detection_engine`
31. `technology_impact_engine`

## Mechanical enforcement boundary

`contracts/v2/cognitive-engine-inventory.schema.json` and
`validate_cognitive_engine_inventory` lock the three engine layers, their order,
their repository-configured counts, exact repository-configured Aurion records, zero-entry CKC/NGK
collections, non-counting metadata, and non-authorising status. These are
implementation-defined V2 integrity mechanics. They do not authenticate the
provisionally attributed inventories, provide the missing names or semantics, or make DTN interchangeable
with any cognitive layer.
