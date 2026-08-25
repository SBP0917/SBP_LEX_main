class EngineResult:
    def __init__(
        self,
        ok: bool,
        name: str,
        detail: str = "",
        data: dict[str, object] | None = None,
    ) -> None:
        self.ok = ok
        self.name = name
        self.detail = detail
        self.data = data or {}

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "name": self.name,
            "detail": self.detail,
            "data": self.data,
        }
