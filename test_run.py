from sbp_lex.pipeline.runner import run_v2_pipeline


payload = {
    "action": "test_action",
    "payload": {
        "assurance_tier": "general",
        "output": {
            "fact_verified_ratio": 0.99999
        }
    },
    "context": {},
    "resolved_authority": "test_authority",
    "jurisdiction": "test_jurisdiction",
    "anchors": {
        "procedural_truth": True,
        "sovereign_knowledge_graph": True,
        "digital_twin_network": True,
        "planetary_population_constraints": True,
    },
    "attestation": {
        "verified": True,
        "attested": True,
    },
    "attestation_consensus": True,
    "truth_anchor": True,
    "truth_continuity": True,
    "truth_expiry": False,
    "truth_revocation": False,
    "sources": [
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
    ],
    "financial_amount": 100.0,
    "safety_profile": {
        "human_safety": 0,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 1,
    },
}

result = run_v2_pipeline(payload)
print(result)
