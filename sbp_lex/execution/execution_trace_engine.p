from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import time


@register("execution_trace")
def execution_trace_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")
    decision_token = payload.get("decision_token")
    audit_record = payload.get("audit_record")

    timestamp = int(time.time())

    trace_material = f"{action}|{jurisdiction}|{authority}|{decision_token}|{audit_record}|{timestamp}"
    trace_hash = hashlib.sha512(trace_material.encode()).hexdigest()

    record = {
        "timestamp": timestamp,
        "action": action,
        "jurisdiction": jurisdiction,
        "authority": authority,
        "decision_token_present": decision_token is not None,
        "audit_record_present": audit_record is not None,
        "trace_hash": trace_hash
    }

    return EngineResult(
        ok=True,
        name="execution_trace",
        detail="Execution trace recorded",
        data={"execution_trace": record}
    )
