"""Celery tasks for chat_api.

Importing this module raises ImportError when `celery` isn't installed; this
is intentional -- `chat_api.services.llm.dispatch_inference` catches it and
falls back to running inference inline (e.g. in the local/test venv, which
doesn't have the Phase 2 async deps).
"""
from celery import shared_task


@shared_task
def run_inference(message_id):
    from chat_api.services.llm import execute_inference
    execute_inference(message_id)
