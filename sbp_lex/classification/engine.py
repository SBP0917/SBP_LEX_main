from typing import Dict, Any


class ClassificationEngine:
    name = "classification_engine"

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        from .router import run_classification
        return run_classification(state)
