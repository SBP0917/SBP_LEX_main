"""Typed fail-closed errors for P/T/D/E verification."""

from __future__ import annotations


class PTDEVerificationError(ValueError):
    """Raised on the first mechanically invalid P/T/D/E condition."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or not code:
            code = "PTDE_VERIFICATION_ERROR"
        self.code = code
        super().__init__(code)


def reject(code: str) -> PTDEVerificationError:
    return PTDEVerificationError(code)


__all__ = ["PTDEVerificationError", "reject"]
