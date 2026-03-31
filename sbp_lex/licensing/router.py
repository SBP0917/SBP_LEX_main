from typing import Dict, Any


def run_licensing(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("licensing_trace", [])

    license_profile = state.get("license_profile")
    ap_acf_class = state.get("ap_acf_class")
    requested_autonomy_level = state.get("requested_autonomy_level")

    state["licensing_trace"].append({
        "layer": "licensing",
        "status": "START"
    })

    if not license_profile:
        state["licensing_result"] = "ESCALATE"
        state["licensing_reason"] = "license_profile_missing"
        return state

    allowed_classes = license_profile.get("allowed_classes", [])
    max_autonomy = license_profile.get("max_autonomy_level")

    if allowed_classes and ap_acf_class not in allowed_classes:
        state["licensing_result"] = "DENY"
        state["licensing_reason"] = "class_not_permitted"
        return state

    if max_autonomy is not None and requested_autonomy_level is not None:
        if float(requested_autonomy_level) > float(max_autonomy):
            state["licensing_result"] = "DENY"
            state["licensing_reason"] = "autonomy_exceeds_license"
            return state

    state["licensing_result"] = "ALLOW"
    state["licensing_reason"] = "license_valid"

    state["licensing_trace"].append({
        "layer": "licensing",
        "result": "ALLOW",
        "reason": "license_valid"
    })

    return state
