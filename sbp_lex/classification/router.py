from typing import Dict, Any


def run_classification(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("classification_trace", [])

    # Inputs
    ap_acf_class = state.get("ap_acf_class")
    ap_acf_subclass = state.get("ap_acf_subclass")
    requested_autonomy_level = state.get("requested_autonomy_level")
    operational_environment = state.get("operational_environment")
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
        }
    )

    # Mandatory minimum
    if not ap_acf_class:
        state["classification_result"] = "ESCALATE"
        state["classification_reason"] = "ap_acf_class_missing"
        state["classification_trace"].append(
            {
                "layer": "classification",
                "result": "ESCALATE",
                "reason": "ap_acf_class_missing",
            }
        )
        return state

    valid_classes = {"CLASS_1", "CLASS_2", "CLASS_3", "CLASS_4", "CLASS_4A", "CLASS_4B", "CLASS_5", "CLASS_5A", "CLASS_5B"}
    if ap_acf_class not in valid_classes:
        state["classification_result"] = "DENY"
        state["classification_reason"] = "invalid_ap_acf_class"
        state["classification_trace"].append(
            {
                "layer": "classification",
                "result": "DENY",
                "reason": "invalid_ap_acf_class",
                "ap_acf_class": ap_acf_class,
            }
        )
        return state

    # Autonomy ceiling sanity guidance by class
    if requested_autonomy_level is not None:
        try:
            requested_autonomy_level = float(requested_autonomy_level)
            state["requested_autonomy_level"] = requested_autonomy_level
        except (TypeError, ValueError):
            state["classification_result"] = "ESCALATE"
            state["classification_reason"] = "invalid_autonomy_level"
            state["classification_trace"].append(
                {
                    "layer": "classification",
                    "result": "ESCALATE",
                    "reason": "invalid_autonomy_level",
                }
            )
            return state

        if requested_autonomy_level < 0 or requested_autonomy_level > 100:
            state["classification_result"] = "DENY"
            state["classification_reason"] = "autonomy_level_out_of_range"
            state["classification_trace"].append(
                {
                    "layer": "classification",
                    "result": "DENY",
                    "reason": "autonomy_level_out_of_range",
                    "requested_autonomy_level": requested_autonomy_level,
                }
            )
            return state

    # Environment/profile minimums
    if operational_environment is None:
        state["classification_result"] = "ESCALATE"
        state["classification_reason"] = "operational_environment_missing"
        state["classification_trace"].append(
            {
                "layer": "classification",
                "result": "ESCALATE",
                "reason": "operational_environment_missing",
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
            "derived_flags": derived_flags,
        }
    )

    return state
