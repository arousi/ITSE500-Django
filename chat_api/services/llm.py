"""Async LLM execution service for chat_api.

`call_provider` is the sole seam to the actual LLM provider (litellm). It is
imported lazily inside the function so this module -- and therefore
`execute_inference`/`dispatch_inference` -- can be imported and unit tested
without litellm/openai installed. Tests patch `chat_api.services.llm.call_provider`
directly (see chat_api/test_llm_execution.py).
"""
import logging
import uuid

from django.db import connection, transaction

from chat_api.services.state import transition_message

logger = logging.getLogger(__name__)


def call_provider(request) -> dict:
    """Call the configured LLM provider for a MessageRequest and normalize the result.

    Returns a dict: {"response_id", "model", "output_text",
    "usage": {"input_tokens", "output_tokens", "total_tokens"}}.
    """
    import litellm  # lazy import: keeps this module importable without litellm installed

    messages = []
    if request.request_system_prompt:
        messages.append({"role": "system", "content": request.request_system_prompt})
    messages.append({"role": "user", "content": request.request_user_content})

    completion = litellm.completion(
        model=request.request_model,
        messages=messages,
        temperature=request.request_temperature,
        max_tokens=request.request_max_tokens,
    )

    usage = getattr(completion, "usage", None) or {}
    # A valid completion must never be discarded over a missing provider id --
    # synthesize a local one so downstream MessageResponse/MessageOutput rows
    # (which key off response_id) always get created.
    response_id = getattr(completion, "id", None) or f"local-{uuid.uuid4()}"
    return {
        "response_id": response_id,
        "model": getattr(completion, "model", request.request_model),
        "output_text": completion.choices[0].message.content,
        "usage": {
            "input_tokens": getattr(usage, "prompt_tokens", None),
            "output_tokens": getattr(usage, "completion_tokens", None),
            "total_tokens": getattr(usage, "total_tokens", None),
        },
    }


def execute_inference(message_id):
    """Run (or no-op) LLM inference for a Message.

    Idempotent: a Message not in "pending" status is left untouched (terminal
    states are never re-executed; this also protects against duplicate
    dispatch/delivery of the same job).

    Uses a claim pattern to fix a concurrency race that existed when the whole
    call (including the provider round-trip) happened inside one transaction:

    Phase 1 -- atomically CLAIM the message: lock the row (where supported),
    verify it is still "pending", and transition it to "streaming" before
    releasing the lock. Two concurrent dispatches of the same message_id can
    then never both proceed past the claim.

    Phase 2 -- call the provider OUTSIDE the lock/transaction (no long-held DB
    lock/connection during a potentially slow network call), then persist the
    result (success -> "complete", failure -> "error" with the failure reason
    recorded on a MessageResponse) in its own short transaction.
    """
    from chat_api.models.message import Message
    from chat_api.models.message_response import MessageResponse
    from chat_api.models.message_output import MessageOutput

    # Phase 1 -- claim the message.
    with transaction.atomic():
        qs = Message.objects.select_related("request_id")
        # select_for_update() is a no-op-equivalent on SQLite (no row locking
        # support there) but matters on Postgres/prod; guard so tests running
        # against SQLite never raise.
        if connection.features.has_select_for_update:
            qs = qs.select_for_update()
        message = qs.get(pk=message_id)

        if message.status != "pending":
            logger.info(
                "llm.execute_inference.skipped_not_pending",
                extra={"message_id": str(message_id), "status": message.status},
            )
            return

        transition_message(message, "streaming")
        message.save()

    # Phase 2 -- call the provider outside the lock.
    try:
        result = call_provider(message.request_id)

        with transaction.atomic():
            response = MessageResponse.objects.create(
                response_id=result["response_id"],
                model_name=result["model"],
                status="completed",
                usage_input_tokens=result["usage"].get("input_tokens"),
                usage_output_tokens=result["usage"].get("output_tokens"),
                usage_total_tokens=result["usage"].get("total_tokens"),
            )
            output = MessageOutput.objects.create(
                output_id=result["response_id"],
                output_type="message",
                output_role="assistant",
                output_content_text=result["output_text"],
            )

            message.response_id = response
            message.output_id = output
            transition_message(message, "complete")  # streaming -> complete (legal)
            message.save()

        logger.info(
            "llm.execute_inference.completed",
            extra={"message_id": str(message_id), "response_id": str(result["response_id"])},
        )
    except Exception as exc:
        with transaction.atomic():
            # Re-fetch: message.status here is "streaming" in the DB (set in
            # Phase 1); refresh so transition_message sees the real current
            # state rather than the stale in-memory value.
            message.refresh_from_db()
            err = MessageResponse.objects.create(
                response_id=f"error-{uuid.uuid4()}",
                status="failed",
                error=str(exc)[:2000],
            )
            message.response_id = err
            transition_message(message, "error")  # streaming -> error (legal); reason recorded
            message.save()

        logger.error(
            "llm.execute_inference.failed",
            extra={"message_id": str(message_id), "error": str(exc)},
        )


def dispatch_inference(message_id):
    """Kick off inference asynchronously via Celery, falling back to inline
    execution when Celery isn't installed (e.g. local dev / test venv without
    the Phase 2 async deps) OR when the broker is unreachable -- never let the
    request 500 or the message hang in "pending" forever.
    """
    try:
        from chat_api.tasks import run_inference
    except ImportError:
        execute_inference(message_id)
        return

    try:
        run_inference.delay(message_id)
    except Exception:
        logger.warning(
            "dispatch_inference: broker unavailable, running inline",
            extra={"message_id": str(message_id)},
        )
        execute_inference(message_id)
