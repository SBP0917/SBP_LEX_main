from datetime import datetime
from typing import Dict, Any
import hashlib
import json


def record_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    record = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "jurisdiction": state.get("jurisdiction"),
        "action": state.get("action"),
        "endpoint": state.get("endpoint"),
        "result": state.get("governance_result"),
        "reason": state.get("governance_reason"),
        "trace": state.get("governance_trace"),
    }

    payload = json.dumps(record, sort_keys=True).encode()
    record_hash = hashlib.sha256(payload).hexdigest()

    state["audit_record"] = record
    state["audit_hash"] = record_hash

    return state
  
