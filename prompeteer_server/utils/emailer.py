import os
import smtplib
from socket import socket
import time
import requests
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
import logging
from typing import Iterable

logger = logging.getLogger("emailer")

# Always prefer environment variable (works for .env, app.yaml, and settings.py)
ZERUH_API_KEY = os.environ.get("ZERUH_API_KEY") or getattr(settings, "ZERUH_API_KEY", None)
ZERUH_BASE_URL = "https://api.zeruh.com/v1"

class ZeruhEmailVerifier:
    @staticmethod
    def verify(email, ip_address=None, timeout=20):
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
            logger.error(f"Zeruh verify failed: {e}")
            return None

    @staticmethod
    def account_info():
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
            logger.error(f"Zeruh account info failed: {e}")
            return None

def send_verified_email(
    subject,
    message,
    recipient_list: Iterable[str],
    from_email=None,
    html_message=None,
    verify_with_zeruh=True,
    zeruh_min_score=70,
    fail_silently=False,
    max_attempts: int = 3,
    attempt_backoff_seconds: float = 0.5,
    **kwargs
):
    """
    Send an email after verifying recipients with Zeruh.

    Behaviour:
      - If verify_with_zeruh=True, call ZeruhEmailVerifier.verify(email).
        * If Zeruh responds with success and status in ("deliverable","risky")
          and score >= zeruh_min_score -> attempt to send.
        * If Zeruh responds but marks undeliverable or low score -> DO NOT SEND.
        * If Zeruh API call fails (None or exception) -> attempt a fallback direct send
          (best-effort) but include verification result=None and flag in result.
      - Perform up to max_attempts sends with exponential backoff between attempts.
      - Returns a dict of per-recipient results:
          {
            "<email>": {
               "sent": bool,
               "attempts": int,
               "verification": {...} | None,
               "reason": str | None,
               "error": str | None
            }
          }
    """
    results = {}
    if not recipient_list:
        return results

    for email in recipient_list:
        result = {"sent": False, "attempts": 0, "verification": None, "reason": None, "error": None}
        proceed_to_send = True
        zeruh_failed = False

        if verify_with_zeruh:
            try:
                verification = ZeruhEmailVerifier.verify(email)
            except Exception as e:
                logger.exception("Zeruh verify raised unexpected exception")
                verification = None

            result["verification"] = verification
            if not verification or not verification.get("success"):
                # Zeruh API error/unavailable -> attempt fallback send but mark verification failure
                zeruh_failed = True
                result["reason"] = "Zeruh error or unavailable"
                proceed_to_send = True  # try fallback
                logger.warning("Zeruh verify unavailable for %s; attempting fallback send", email)
            else:
                # Check Zeruh verdict
                verdict = verification.get("result", {}) or {}
                status = verdict.get("status")
                score = verdict.get("score", 0)
                if status not in ("deliverable", "risky") or (score or 0) < zeruh_min_score:
                    result["reason"] = f"Zeruh status={status}, score={score}"
                    proceed_to_send = False
                    logger.info("Skipping send to %s due to Zeruh verdict: %s", email, result["reason"])
                else:
                    proceed_to_send = True

        if not proceed_to_send:
            results[email] = result
            continue

        # Attempt sending with retries
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
                    msg.content_subtype = "html"
                    msg.body = html_message
                sent_count = msg.send(fail_silently=False)
                result["attempts"] = attempts
                if sent_count and sent_count > 0:
                    result["sent"] = True
                    sent = True
                    logger.info("Email sent to %s (attempt %d)", email, attempt)
                    break
                else:
                    last_error = "Email backend reported 0 delivered"
                    logger.warning("Email backend returned 0 for %s on attempt %d", email, attempt)
            except (smtplib.SMTPException, socket.error) as e:
                last_error = str(e)
                logger.warning("SMTP/socket error sending to %s on attempt %d: %s", email, attempt, e)
            except Exception as e:
                last_error = str(e)
                logger.exception("Unexpected error sending to %s on attempt %d: %s", email, attempt, e)

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

        results[email] = result

    return results