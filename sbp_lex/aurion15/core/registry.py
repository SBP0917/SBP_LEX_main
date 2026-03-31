from typing import Dict, List


ENGINE_REGISTRY = {
    "classification_engine": {
        "stage": 1,
        "reads": ["ap_acf_class", "requested_autonomy_level"],
        "writes": ["classification_result", "classification_reason"],
        "depends_on": []
    },
    "licensing_engine": {
        "stage": 2,
        "reads": ["license_profile", "ap_acf_class"],
        "writes": ["licensing_result", "licensing_reason"],
        "depends_on": ["classification_engine"]
    },
    "governance_engine": {
        "stage": 3,
        "reads": ["jurisdiction"],
        "writes": ["governance_result", "governance_reason"],
        "depends_on": ["licensing_engine"]
    }
}
