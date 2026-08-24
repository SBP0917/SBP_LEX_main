# AP-ACF Blueprint-Derived V2 Mapping

Status: `IMPLEMENTATION_DEFINED_V2`; authority status:
`AI_PROPOSED_AWAITING_APPROVAL`.

Source boundary: the mapping below is derived only from the repository
extraction at
`tmp/documents/patent_matrix_sources/bp01_apacf/extracted.txt`, identified there
as the B01 *Australia & Pacific Autonomy Classification Framework* blueprint.
It is blueprint-derived repository evidence, not filed wording and not an
owner-approved or authoritative classification policy.

## Mechanically admitted mapping

- Exact class identifiers: `CLASS_1`, `CLASS_2`, `CLASS_3`, `CLASS_4`,
  `CLASS_4A`, `CLASS_4B`, `CLASS_5`, `CLASS_5A`, and `CLASS_5B`.
- A base `CLASS_4` profile may identify `CLASS_4`, `CLASS_4A`, or `CLASS_4B` as
  its subclass. A base `CLASS_5` profile may identify `CLASS_5`, `CLASS_5A`, or
  `CLASS_5B`. A profile using a subclass as its class identifier must repeat
  that exact identifier as its subclass.
- The only exact numeric ceilings stated by B01 are `CLASS_5` = 50,
  `CLASS_5B` = 75, and `CLASS_5A` = 100. The implementation does not invent
  numeric ceilings for Classes 1-4; it requires a declared ceiling and ensures
  requested autonomy does not exceed it.
- The three classification dimensions are required: autonomy level, public
  exposure, and operational scope.
- The operational environment and all three named environment modifiers are
  required: human proximity, geographic isolation, and operational containment.

Unknown classes, class/subclass mismatches, absent or invalid ceilings, requests
above the declared ceiling, and missing environment inputs produce `DENY`.

## Environmental adjustment boundary

B01 says classification *may* be modified based on environment and gives a
mining example, but supplies no deterministic downgrade formula or controlled
vocabulary. The V2 mechanic therefore records and requires the named inputs but
does not infer a class downgrade. Any future adjustment rule remains
`SOURCE_UNAVAILABLE` until an evidenced deterministic rule is selected by a
bounded V2 design decision.

The classification result is an application-level mechanical result. It grants
no licence, authority, execution permission, or filed conformance.
