from __future__ import annotations

from .models import Principal


class PolicyViolation(ValueError):
    pass


def assert_read_only_discovery(provider: str) -> None:
    if provider not in {"aws", "azure", "terraform", "sample"}:
        raise PolicyViolation("Unsupported discovery provider.")


def assert_approval_allowed(principal: Principal) -> None:
    if not ({"inframind_approver", "inframind_admin"} & principal.roles):
        raise PolicyViolation("An InfraMind approver or administrator role is required.")


def assert_pull_request_allowed(principal: Principal) -> None:
    assert_approval_allowed(principal)
