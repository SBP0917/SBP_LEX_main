from typing import Dict, Any

from sbp_lex.governance.authority_provenance import (
    verify_authority_provenance,
)


# Blueprint-derived IMPLEMENTATION_DEFINED_V2 admission mechanics.  B01 gives
# exact numeric ceilings only for the Class 5 family; no ceiling is invented for
# Classes 1-4.
AP_ACF_SCHEMA_STATUS = "IMPLEMENTATION_DEFINED_V2"
AP_ACF_AUTHORITY_STATUS = "AI_PROPOSED_AWAITING_APPROVAL"
AP_ACF_CLASS_SUBCLASSES = {
    "CLASS_1": frozenset({"CLASS_1"}),
    "CLASS_2": frozenset({"CLASS_2"}),
    "CLASS_3": frozenset({"CLASS_3"}),
    "CLASS_4": frozenset({"CLASS_4", "CLASS_4A", "CLASS_4B"}),
    "CLASS_4A": frozenset({"CLASS_4A"}),
    "CLASS_4B": frozenset({"CLASS_4B"}),
    "CLASS_5": frozenset({"CLASS_5", "CLASS_5A", "CLASS_5B"}),
    "CLASS_5A": frozenset({"CLASS_5A"}),
    "CLASS_5B": frozenset({"CLASS_5B"}),
}
AP_ACF_EXACT_CLASS_5_CEILINGS = {
    "CLASS_5": 50,
    "CLASS_5B": 75,
    "CLASS_5A": 100,
}
AP_ACF_REQUIRED_ENVIRONMENT_MODIFIERS = (
    "human_proximity",
    "geographic_isolation",
    "operational_containment",
)


def evaluate_ap_acf_profile(state: Dict[str, Any]) -> tuple[bool, str]:
    """Evaluate the source-bounded B01 profile without granting authority."""

    class_id = state.get("ap_acf_class")
    subclass_id = state.get("ap_acf_subclass")
    requested = state.get("requested_autonomy_level")
    declared_ceiling = state.get("autonomy_ceiling")

    if type(class_id) is not str:
        return False, "ap_acf_class_unknown"
    allowed_subclasses = AP_ACF_CLASS_SUBCLASSES.get(class_id)
    if allowed_subclasses is None:
        return False, "ap_acf_class_unknown"
    if subclass_id not in allowed_subclasses:
        return False, "ap_acf_subclass_mismatch"

    if type(requested) is not int:
        return False, "requested_autonomy_level_missing_or_invalid"
    if requested < 0 or requested > 100:
        return False, "autonomy_level_out_of_range"
    if type(declared_ceiling) is not int:
        return False, "autonomy_ceiling_missing_or_invalid"
    if declared_ceiling < 0 or declared_ceiling > 100:
        return False, "autonomy_ceiling_out_of_range"

    effective_class = subclass_id
    exact_ceiling = AP_ACF_EXACT_CLASS_5_CEILINGS.get(effective_class)
    if exact_ceiling is not None and declared_ceiling != exact_ceiling:
        return False, "ap_acf_class_ceiling_mismatch"
    if requested > declared_ceiling:
        return False, "requested_autonomy_exceeds_ceiling"

    for field in (
        "operational_environment",
        "public_exposure",
        "operational_scope",
    ):
        if state.get(field) in (None, ""):
            return False, f"{field}_missing"

    modifiers = state.get("environment_modifiers")
    if type(modifiers) is not dict:
        return False, "environment_modifiers_missing_or_invalid"
    for modifier in AP_ACF_REQUIRED_ENVIRONMENT_MODIFIERS:
        if modifiers.get(modifier) in (None, ""):
            return False, f"environment_modifier_{modifier}_missing"

    return True, "classification_profile_accepted"


def run_classification(
    state: Dict[str, Any],
    *,
    authority_provenance_dependencies: Any | None = None,
) -> Dict[str, Any]:
    state.setdefault("classification_trace", [])

    # Inputs
    ap_acf_class = state.get("ap_acf_class")
    ap_acf_subclass = state.get("ap_acf_subclass")
    public_exposure = state.get("public_exposure")
    operational_scope = state.get("operational_scope")
    environment_modifiers = state.get("environment_modifiers") or {}

    # Defaults
    state["classification_result"] = None
    state["classification_reason"] = None
    state["classification_trace"].append(
            {
                "layer": "classification",
                "status": "START",
                "schema_status": AP_ACF_SCHEMA_STATUS,
                "authority_status": AP_ACF_AUTHORITY_STATUS,
            }
    )

    if not verify_authority_provenance(
        state,
        dependencies=authority_provenance_dependencies,
        require_hash_binding=True,
    ):
        state["classification_result"] = "DENY"
        state["classification_reason"] = (
            "authority_provenance_not_current_and_valid"
        )
        state["classification_trace"].append(
            {
                "layer": "classification",
                "result": "DENY",
                "reason": state["classification_reason"],
            }
        )
        return state

    profile_valid, profile_reason = evaluate_ap_acf_profile(state)
    if not profile_valid:
        state["classification_result"] = "DENY"
        state["classification_reason"] = profile_reason
        state["classification_trace"].append(
            {
                "layer": "classification",
                "result": "DENY",
                "reason": profile_reason,
            }
        )
        return state

    # Modifier extraction
    human_proximity = environment_modifiers.get("human_proximity")
    geographic_isolation = environment_modifiers.get("geographic_isolation")
    operational_containment = environment_modifiers.get("operational_containment")

    # Basic dynamic profile notes
    derived_flags = {
        "human_proximity": human_proximity,
        "geographic_isolation": geographic_isolation,
        "operational_containment": operational_containment,
        "public_exposure": public_exposure,
        "operational_scope": operational_scope,
    }

    # Classification pass
    state["classification_result"] = "ALLOW"
    state["classification_reason"] = "classification_profile_accepted"
    state["classification_trace"].append(
        {
            "layer": "classification",
            "result": "ALLOW",
            "reason": "classification_profile_accepted",
            "ap_acf_class": ap_acf_class,
            "ap_acf_subclass": ap_acf_subclass,
            "schema_status": AP_ACF_SCHEMA_STATUS,
            "authority_status": AP_ACF_AUTHORITY_STATUS,
            "derived_flags": derived_flags,
        }
    )

    return state
