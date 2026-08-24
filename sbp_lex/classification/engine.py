from typing import Dict, Any


class ClassificationEngine:
    name = "classification_engine"

    def execute(
        self,
        state: Dict[str, Any],
        *,
        authority_provenance_dependencies: Any | None = None,
    ) -> Dict[str, Any]:
        from .router import run_classification
        return run_classification(
            state,
            authority_provenance_dependencies=(
                authority_provenance_dependencies
            ),
        )
