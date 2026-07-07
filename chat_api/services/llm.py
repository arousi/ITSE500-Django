"""Async LLM execution service for chat_api.

`call_provider` is the sole seam to the actual LLM provider (litellm). It is
imported lazily inside the function so this module -- and therefore
`execute_inference`/`dispatch_inference` -- can be imported and unit tested
without litellm/openai installed. Tests patch `chat_api.services.llm.call_provider`
directly (see chat_api/test_llm_execution.py).
"""
import logging

from django.db import transaction

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
    return {
        "response_id": getattr(completion, "id", None),
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
    """
    from chat_api.models.message import Message
    from chat_api.models.message_response import MessageResponse
    from chat_api.models.message_output import MessageOutput

    message = Message.objects.select_related("request_id").get(pk=message_id)

    if message.status != "pending":
        logger.info(
            "llm.execute_inference.skipped_not_pending",
            extra={"message_id": str(message_id), "status": message.status},
        )
        return

    try:
        with transaction.atomic():
            result = call_provider(message.request_id)

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
            transition_message(message, "complete")
            message.save()

        logger.info(
            "llm.execute_inference.completed",
            extra={"message_id": str(message_id), "response_id": str(result["response_id"])},
        )
    except Exception as exc:
        logger.error(
            "llm.execute_inference.failed",
            extra={"message_id": str(message_id), "error": str(exc)},
        )
        transition_message(message, "error")
        message.save()


def dispatch_inference(message_id):
    """Kick off inference asynchronously via Celery, falling back to inline
    execution when Celery isn't installed (e.g. local dev / test venv without
    the Phase 2 async deps).
    """
    try:
        from chat_api.tasks import run_inference
        run_inference.delay(message_id)
    except ImportError:
        execute_inference(message_id)
