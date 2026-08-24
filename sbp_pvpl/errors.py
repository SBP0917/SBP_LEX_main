"""Fail-closed errors for the detached V2 publication layer."""

from __future__ import annotations


class PVPLValidationError(ValueError):
    """A stable, non-sensitive V2 PVPL rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def reject(code: str) -> PVPLValidationError:
    return PVPLValidationError(code)


__all__ = ["PVPLValidationError"]
