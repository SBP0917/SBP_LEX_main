from typing import Dict, Any
from .state_schema import STATE_TEMPLATE


def build_state(input_data: Dict[str, Any]) -> Dict[str, Any]:
    state = STATE_TEMPLATE.copy()

    for key in state.keys():
        if key in input_data:
            state[key] = input_data[key]

    return state
