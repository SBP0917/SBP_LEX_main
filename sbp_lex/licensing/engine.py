from typing import Dict, Any


class LicensingEngine:
    name = "licensing_engine"

    def execute(
        self,
        state: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        from .router import run_licensing
        return run_licensing(state, **kwargs)
