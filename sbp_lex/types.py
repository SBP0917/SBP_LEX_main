class EngineResult:
    def __init__(self, ok: bool = True, detail: str = "pass", data=None):
        self.ok = ok
        self.detail = detail
        self.data = data
