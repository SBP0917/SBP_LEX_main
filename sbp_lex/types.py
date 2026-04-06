from sbp_lex.shared.types import EngineResult

class EngineResult:
    def __init__(self, ok: bool, name: str, detail: str = "", data: dict = None):
        self.ok = ok
        self.name = name
        self.detail = detail
        self.data = data or {}

    def to_dict(self):
        return {
            "ok": self.ok,
            "name": self.name,
            "detail": self.detail,
            "data": self.data,
        }
