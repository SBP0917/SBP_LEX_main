from sbp_lex.pipeline.runner import run_pipeline

state = {
    "action": "test_action",
    "financial_amount": 1000,
    "sources": [
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
        {"verified": True, "attested": True, "fresh": True, "consistent": True},
    ],
    "safety_profile": {
        "human_safety": 1,
        "irreversibility": 1,
        "cascading_impact": 1,
        "financial_operational": 0
    }
}

result = run_pipeline(state)

print("\n--- RESULT ---\n")
for k, v in result.items():
    print(f"{k}: {v}")
