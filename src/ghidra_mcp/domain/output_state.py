"""What a failed write left behind, as ``details.output_state``.

``absent``: nothing changed, so a transient failure can be retried.
``created``: changes remain in the program, unsaved.  ``uncertain``: inspect
the program before continuing.  Every layer that reports it uses these
helpers, so a program write, a job and a project or repository write agree.
"""

from __future__ import annotations

from .error_codes import REFUSED_BEFORE_ANY_CHANGE
from .errors import DomainError

ABSENT = "absent"
CREATED = "created"
UNCERTAIN = "uncertain"

# From how the core's transaction recorder or a script run says its
# transactions ended (ghidra_headless.session.transactions); an unknown
# outcome leaves the output uncertain.
_BY_TRANSACTION_OUTCOME = {"unchanged": ABSENT, "rolled_back": ABSENT, "committed": CREATED}


def output_state_for_outcome(outcome: str | None) -> str:
    return _BY_TRANSACTION_OUTCOME.get(outcome or "", UNCERTAIN)


def retryable_after(retryable: bool, output_state: str | None) -> bool:
    """A transient cause is worth retrying only when the failure left nothing behind."""
    return bool(retryable) and output_state == ABSENT


def says_nothing_changed(error: DomainError) -> bool:
    """Whether a failure's code says it left nothing: a refusal before any change, or a transient (retryable) one."""
    return error.retryable or error.code in REFUSED_BEFORE_ANY_CHANGE


def with_output_state(error: DomainError, output_state: str) -> DomainError:
    return DomainError(
        code=error.code,
        message=error.message,
        hint=error.hint,
        retryable=retryable_after(error.retryable, output_state),
        details={**(error.details or {}), "output_state": output_state},
    )


__all__ = [
    "ABSENT",
    "CREATED",
    "UNCERTAIN",
    "output_state_for_outcome",
    "retryable_after",
    "says_nothing_changed",
    "with_output_state",
]
