# ...existing code...
import os
import json
import smtplib
import socket
import time
import requests
from typing import Iterable, Optional
import logging

from django.conf import settings
from django.core.mail import EmailMessage

logger = logging.getLogger("emailer")

# Always prefer environment variable (works for .env, app.yaml, and settings.py)
ZERUH_API_KEY = os.environ.get("ZERUH_API_KEY") or getattr(settings, "ZERUH_API_KEY", None)
ZERUH_BASE_URL = "https://api.zeruh.com/v1"

# Maileroo configuration (env var or Django settings)
MAILEROO_API_KEY = os.environ.get("MAILEROO_API_KEY") or getattr(settings, "MAILEROO_API_KEY", None)
MAILEROO_SEND_URL = getattr(settings, "MAILEROO_SEND_URL", "https://api.maileroo.example/v1/send")


class ZeruhEmailVerifier:
    @staticmethod
    def verify(email: str, ip_address: Optional[str] = None, timeout: int = 20) -> Optional[dict]:
        """
        Verify an email address using Zeruh.
        Returns the Zeruh API response as dict, or None on error.
        """
        if not ZERUH_API_KEY:
            logger.warning("ZERUH_API_KEY not set in environment or settings.")
            return None

        params = {"email_address": email, "timeout": timeout, "api_key": ZERUH_API_KEY}
        if ip_address:
            params["ip_address"] = ip_address

        try:
            resp = requests.get(
                f"{ZERUH_BASE_URL}/verify",
                params=params,
                timeout=timeout + 5,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.exception("Zeruh verify failed for %s: %s", email, e)
            return None

    @staticmethod
    def account_info() -> Optional[dict]:
        """
        Get Zeruh account info (credits, etc).
        """
        if not ZERUH_API_KEY:
            logger.warning("ZERUH_API_KEY not set in environment or settings.")
            return None
        try:
            resp = requests.get(
                f"{ZERUH_BASE_URL}/account",
                params={"api_key": ZERUH_API_KEY},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.exception("Zeruh account info failed: %s", e)
            return None


class MailerooClient:
    @staticmethod
    def send_email(subject: str, message: str, to_email: str, from_email: Optional[str] = None, html_message: Optional[str] = None, timeout: int = 10) -> dict:
        """
        Send email via Maileroo API.
        Returns dict: { "success": bool, "status_code": int|None, "body": dict|str|None, "error": str|None }
        """
        if not MAILEROO_API_KEY:
            return {"success": False, "status_code": None, "body": None, "error": "MAILEROO_API_KEY not configured"}

        payload = {
            "subject": subject,
            "to": to_email,
            "from": from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None),
            "text": message,
        }
        if html_message:
            payload["html"] = html_message

        headers = {
            "Authorization": f"Bearer {MAILEROO_API_KEY}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(MAILEROO_SEND_URL, headers=headers, json=payload, timeout=timeout)
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            success = 200 <= resp.status_code < 300
            return {"success": success, "status_code": resp.status_code, "body": body, "error": None if success else f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.exception("Maileroo send_email exception for %s: %s", to_email, e)
            return {"success": False, "status_code": None, "body": None, "error": str(e)}


def send_verified_email(
    subject: str,
    message: str,
    recipient_list: Iterable[str],
    from_email: Optional[str] = None,
    html_message: Optional[str] = None,
    verify_with_zeruh: bool = True,
    zeruh_min_score: int = 10,
    fail_silently: bool = False,
    max_attempts: int = 3,
    attempt_backoff_seconds: float = 0.5,
    use_maileroo_if_deliverable: bool = True,
    **kwargs
) -> dict:
    """
    Send an email after verifying recipients with Zeruh and optionally using Maileroo.

    Returns per-recipient results:
      {
        "<email>": {
           "sent": bool,
           "attempts": int,
           "verification": {...} | None,
           "reason": str | None,
           "error": str | None,
           "maileroo": {...} | None
        }
      }
    """
    results = {}
    if not recipient_list:
        return results

    for email in recipient_list:
        result = {"sent": False, "attempts": 0, "verification": None, "reason": None, "error": None, "maileroo": None}
        proceed_to_send = True
        zeruh_failed = False
        maileroo_attempted = False

        # Zeruh verification
        if verify_with_zeruh:
            try:
                verification = ZeruhEmailVerifier.verify(email)
            except Exception as e:
                logger.exception("Zeruh verify unexpected error for %s: %s", email, e)
                verification = None

            result["verification"] = verification
            if not verification or not verification.get("success"):
                # Zeruh API error/unavailable -> attempt fallback send but mark verification failure
                zeruh_failed = True
                result["reason"] = "Zeruh error or unavailable"
                proceed_to_send = True  # allow fallback send
                logger.warning("Zeruh verify unavailable for %s; attempting fallback send", email)
            else:
                verdict = verification.get("result", {}) or {}
                status = verdict.get("status")
                score = verdict.get("score", 0) or 0
                if status not in ("deliverable", "risky") or score < zeruh_min_score:
                    result["reason"] = f"Zeruh status={status}, score={score}"
                    proceed_to_send = False
                    logger.info("Skipping send to %s due to Zeruh verdict: %s", email, result["reason"])
                else:
                    proceed_to_send = True

        if not proceed_to_send:
            results[email] = result
            continue

        # If deliverable and Maileroo is configured & allowed, try Maileroo first
        if use_maileroo_if_deliverable and MAILEROO_API_KEY and result.get("verification"):
            verdict = result["verification"].get("result", {}) or {}
            status = verdict.get("status")
            score = (verdict.get("score") or 0)
            if status in ("deliverable", "risky") and score >= zeruh_min_score:
                maileroo_attempted = True
                maileroo_resp = MailerooClient.send_email(subject, message, email, from_email=from_email, html_message=html_message)
                result["maileroo"] = maileroo_resp
                if maileroo_resp.get("success"):
                    result["sent"] = True
                    result["attempts"] = 1
                    logger.info("Maileroo delivered email to %s", email)
                    results[email] = result
                    continue
                else:
                    logger.warning("Maileroo failed for %s: %s; falling back to Django backend", email, maileroo_resp.get("error"))

        # Attempt sending with retries via Django backend (fallback)
        attempts = 0
        sent = False
        last_error = None
        for attempt in range(1, max_attempts + 1):
            attempts = attempt
            try:
                msg = EmailMessage(
                    subject=subject,
                    body=message,
                    from_email=from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    to=[email],
                )
                if html_message:
                    # Use HTML body if provided
                    msg.content_subtype = "html"
                    msg.body = html_message
                sent_count = msg.send(fail_silently=fail_silently)
                result["attempts"] = attempts
                if sent_count and sent_count > 0:
                    result["sent"] = True
                    sent = True
                    logger.info("Email sent to %s (attempt %d) via Django backend", email, attempt)
                    break
                else:
                    last_error = "Email backend reported 0 delivered"
                    logger.warning("Email backend returned 0 for %s on attempt %d", email, attempt)
            except (smtplib.SMTPException, socket.error) as e:
                last_error = str(e)
                logger.warning("SMTP/socket error sending to %s on attempt %d: %s", email, attempt, e)
                if fail_silently:
                    # if failing silently, do not raise; just record and break to avoid noisy retries
                    break
            except Exception as e:
                last_error = str(e)
                logger.exception("Unexpected error sending to %s on attempt %d: %s", email, attempt, e)
                if fail_silently:
                    break

            # backoff before next attempt
            time.sleep(attempt_backoff_seconds * (2 ** (attempt - 1)))

        if not sent:
            result["sent"] = False
            result["attempts"] = attempts
            result["error"] = last_error
            if zeruh_failed and last_error:
                result["reason"] = f"Zeruh unavailable and send failed: {last_error}"
            elif zeruh_failed:
                result["reason"] = "Zeruh unavailable and send not confirmed"
            else:
                result["reason"] = result.get("reason") or "send failed"

            logger.error("Failed to send email to %s after %d attempts: %s", email, attempts, last_error)

        # ensure we report maileroo attempt if attempted
        if maileroo_attempted and result.get("maileroo") is None:
            result["maileroo"] = {"success": False, "error": "maileroo attempted but no response"}

        results[email] = result

    return results