STATE_TEMPLATE = {
    "context": None,
    "jurisdiction": None,
    "action": None,

    # classification
    "ap_acf_class": None,
    "ap_acf_subclass": None,
    "requested_autonomy_level": None,
    "requested_system_mode": None,
    "operational_environment": None,
    "public_exposure": None,
    "operational_scope": None,
    "environment_modifiers": None,

    "classification_result": None,
    "classification_reason": None,
    "classification_trace": [],

    # licensing
    "license_profile": None,
    "licensing_result": None,
    "licensing_reason": None,
    "licensing_trace": [],

    # governance
    "governance_result": None,
    "governance_reason": None,
    "governance_trace": [],

    # domains
    "domain_result": None,
    "domain_trace": [],

    # aurion
    "current_candidate": None,
    "candidate_attempt_count": 0,
    "aurion15_result": None,
    "aurion15_trace": [],

    # execution
    "decision": None,
}
