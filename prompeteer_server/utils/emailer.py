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
MAILEROO_SEND_URL = getattr(settings, "MAILEROO_SEND_URL", "B91FEB7ED85DEAFE.MAILEROO.ORG")


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
    maileroo_max_attempts: int = 3,
    maileroo_backoff_seconds: float = 0.5,
    allow_smtp_fallback: bool = False,   # default: do NOT fallback to Django SMTP
    smtp_max_attempts: int = 3,
    smtp_backoff_seconds: float = 0.5,
    fail_silently: bool = False,
    **kwargs
) -> dict:
    """
    Strict flow:
      - Verify recipient via Zeruh (required when verify_with_zeruh=True).
      - If verdict is deliverable/risky and score >= zeruh_min_score:
          Attempt Maileroo send (with retries). Return per-recipient maileroo result.
      - If verdict is undeliverable/low-score -> do NOT send, return reason.
      - If Zeruh API call fails:
          - If allow_smtp_fallback==True: attempt Django SMTP (best-effort).
          - Otherwise do NOT send and return verification error.
    """
    results = {}
    if not recipient_list:
        return results

    for email in recipient_list:
        r = {"sent": False, "attempts": 0, "verification": None, "reason": None, "error": None, "maileroo": None, "smtp": None}

        # 1) Zeruh verification (if requested)
        verification = None
        if verify_with_zeruh:
            try:
                verification = ZeruhEmailVerifier.verify(email)
            except Exception as e:
                logger.exception("Zeruh verify failed unexpectedly for %s: %s", email, e)
                verification = None
            r["verification"] = verification

            if not verification or not verification.get("success"):
                r["reason"] = "Zeruh unavailable or error"
                # Do not proceed to Maileroo; allow optional SMTP fallback below if configured
                if not allow_smtp_fallback:
                    results[email] = r
                    continue
            else:
                verdict = verification.get("result", {}) or {}
                status = verdict.get("status")
                score = (verdict.get("score") or 0)
                if status not in ("deliverable", "risky") or score < zeruh_min_score:
                    r["reason"] = f"Zeruh verdict prevents send: status={status}, score={score}"
                    results[email] = r
                    continue
                # else: eligible to send via Maileroo

        # 2) Maileroo: attempt as primary sender if configured
        maileroo_used = False
        if MAILEROO_API_KEY:
            maileroo_used = True
            maileroo_attempts = 0
            maileroo_success = False
            last_maileroo_err = None
            for attempt in range(1, maileroo_max_attempts + 1):
                maileroo_attempts = attempt
                try:
                    maileroo_resp = MailerooClient.send_email(subject, message, email, from_email=from_email, html_message=html_message)
                    r["maileroo"] = maileroo_resp
                    if maileroo_resp.get("success"):
                        r["sent"] = True
                        r["attempts"] = maileroo_attempts
                        maileroo_success = True
                        logger.info("Maileroo sent to %s (attempt %d)", email, attempt)
                        break
                    else:
                        last_maileroo_err = maileroo_resp.get("error") or f"HTTP {maileroo_resp.get('status_code')}"
                        logger.warning("Maileroo response for %s attempt %d: %s", email, attempt, last_maileroo_err)
                except Exception as e:
                    last_maileroo_err = str(e)
                    logger.exception("Maileroo exception for %s attempt %d: %s", email, attempt, e)

                time.sleep(maileroo_backoff_seconds * (2 ** (attempt - 1)))

            if maileroo_success:
                results[email] = r
                continue

            # Maileroo exhausted and failed
            r["reason"] = r.get("reason") or "Maileroo failed"
            r["error"] = last_maileroo_err
        else:
            r["reason"] = r.get("reason") or "Maileroo not configured"

        # 3) Optional SMTP fallback (only if explicitly allowed)
        if allow_smtp_fallback:
            smtp_attempts = 0
            smtp_sent = False
            last_smtp_err = None
            for attempt in range(1, smtp_max_attempts + 1):
                smtp_attempts = attempt
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
                    sent_count = msg.send(fail_silently=fail_silently)
                    r["smtp"] = {"sent_count": sent_count}
                    r["attempts"] = smtp_attempts
                    if sent_count and sent_count > 0:
                        r["sent"] = True
                        smtp_sent = True
                        logger.info("SMTP sent to %s (attempt %d)", email, attempt)
                        break
                    else:
                        last_smtp_err = "Email backend reported 0 delivered"
                        logger.warning("SMTP backend returned 0 for %s on attempt %d", email, attempt)
                except Exception as e:
                    last_smtp_err = str(e)
                    logger.exception("SMTP exception for %s on attempt %d: %s", email, attempt, e)
                    if fail_silently:
                        break

                time.sleep(smtp_backoff_seconds * (2 ** (attempt - 1)))

            if smtp_sent:
                results[email] = r
                continue

            r["error"] = r.get("error") or last_smtp_err
            r["reason"] = r.get("reason") or "SMTP fallback failed"

        # 4) If we get here, nothing sent
        results[email] = r

    return results