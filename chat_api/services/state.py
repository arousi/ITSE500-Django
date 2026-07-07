"""SOLE authority for Message.status transitions (see chat_api/test_llm_execution.py).

State machine:
    pending   --success--> complete
    pending   --failure--> error
    streaming --success--> complete
    streaming --failure--> error
    complete / error are terminal.

Any transition not present in ALLOWED_MESSAGE_TRANSITIONS is illegal and raises
InvalidTransition. No other code path should mutate Message.status directly.
"""

ALLOWED_MESSAGE_TRANSITIONS = {
    "pending": {"streaming", "complete", "error"},
    "streaming": {"complete", "error"},
    "complete": set(),
    "error": set(),
}


class InvalidTransition(Exception):
    """Raised when an illegal Message.status transition is attempted."""


def transition_message(message, to_status):
    """Validate and apply a Message.status transition in-memory.

    Does NOT save the message -- the caller is responsible for persisting it
    (typically inside the same transaction as the related side-effects).
    """
    current_status = message.status
    allowed = ALLOWED_MESSAGE_TRANSITIONS.get(current_status, set())
    if to_status not in allowed:
        raise InvalidTransition(
            f"Cannot transition Message {message.pk} from {current_status!r} to {to_status!r}"
        )
    message.status = to_status
    return message
