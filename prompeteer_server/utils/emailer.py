# ...existing code...
import os
import time
import base64
import logging
from typing import Iterable, Optional, Union, List, Dict, Any

import requests

from django.conf import settings
from django.core.mail import EmailMessage

logger = logging.getLogger("emailer")

# Zeruh
ZERUH_API_KEY = os.environ.get("ZERUH_API_KEY") or getattr(settings, "ZERUH_API_KEY", None)
ZERUH_BASE_URL = "https://api.zeruh.com/v1"

# Maileroo configuration
# - MAILEROO_API_KEY : your Maileroo sending key
# - MAILEROO_API_BASE_URL : the Maileroo API base URL (default uses documented endpoint)
# - MAILEROO_SEND_URL : optional full send endpoint; if present it must be a full URL (https://...)
# - MAILEROO_SENDER_DOMAIN : your verified sending domain (used only for constructing from addresses)
# Maileroo configuration
MAILEROO_API_KEY = os.environ.get("MAILEROO_API_KEY") or getattr(settings, "MAILEROO_API_KEY", None)

# Base API endpoint
MAILEROO_API_BASE_URL = os.environ.get("MAILEROO_API_BASE_URL") or getattr(settings, "MAILEROO_API_BASE_URL", "https://smtp.maileroo.com/api/v2/")

# Send endpoint (defaults to /send)
MAILEROO_SEND_URL = os.environ.get("MAILEROO_SEND_URL") or getattr(settings, "MAILEROO_SEND_URL", f"{MAILEROO_API_BASE_URL}/emails")

# SMTP fallback config (only if you want to use Django’s EmailMessage as backup)
MAILEROO_SMTP_HOST = "smtp.maileroo.com"
MAILEROO_SMTP_PORT = 587
MAILEROO_SMTP_USER = "ITSE500-OK-2025@b91feb7ed85deafe.maileroo.org"
MAILEROO_SMTP_PASSWORD = "dde58a8292c2074bd896110b"

# For constructing from addresses
MAILEROO_SENDER_DOMAIN = os.environ.get("MAILEROO_SENDER_DOMAIN") or getattr(settings, "MAILEROO_SENDER_DOMAIN", "b91feb7ed85deafe.maileroo.org")

# Normalize send URL:
def _resolve_maileroo_send_url() -> str:
    # If explicit full send URL provided and looks valid, use it.
    if MAILEROO_SEND_URL:
        if MAILEROO_SEND_URL.lower().startswith("http://") or MAILEROO_SEND_URL.lower().startswith("https://"):
            # If accidentally set to the same value as the sender domain, ignore it and use base endpoint
            if MAILEROO_SENDER_DOMAIN and MAILEROO_SEND_URL.lower().find(MAILEROO_SENDER_DOMAIN.lower()) != -1:
                logger.warning("MAILEROO_SEND_URL appears to be the sender domain; using API base URL instead.")
            else:
                return MAILEROO_SEND_URL
        else:
            # Provided value missing scheme — likely a mistake (domain only). Warn and fall back to base.
            logger.warning("MAILEROO_SEND_URL missing scheme or invalid; falling back to MAILEROO_API_BASE_URL.")
    # Default send endpoint path under base URL
    base = MAILEROO_API_BASE_URL.rstrip("/")
    return f"{base}/emails"

MAILEROO_RESOLVED_SEND_URL = _resolve_maileroo_send_url()


class ZeruhEmailVerifier:
    @staticmethod
    def verify(email: str, ip_address: Optional[str] = None, timeout: int = 20) -> Optional[dict]:
        if not ZERUH_API_KEY:
            logger.debug("Zeruh API key not configured.")
            return None
        params = {"email_address": email, "timeout": timeout, "api_key": ZERUH_API_KEY}
        if ip_address:
            params["ip_address"] = ip_address
        try:
            resp = requests.get(f"{ZERUH_BASE_URL}/verify", params=params, timeout=timeout + 5)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("Zeruh verify failed for %s: %s", email, exc)
            return None

    @staticmethod
    def account_info() -> Optional[dict]:
        if not ZERUH_API_KEY:
            return None
        try:
            resp = requests.get(f"{ZERUH_BASE_URL}/account", params={"api_key": ZERUH_API_KEY}, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("Zeruh account_info failed: %s", exc)
            return None


class MailerooClient:
    @staticmethod
    def _normalize_recipients(to: Union[str, Iterable[str], Iterable[dict]]) -> List[dict]:
        if not to:
            return []
        if isinstance(to, str):
            return [{"address": to}]
        recipients: List[dict] = []
        for item in to:
            if isinstance(item, str):
                recipients.append({"address": item})
            elif isinstance(item, dict):
                recipients.append(item)
        return recipients

    @staticmethod
    def _encode_attachment(att: Any) -> dict:
        if isinstance(att, dict):
            return {
                "file_name": att.get("file_name"),
                "content_type": att.get("content_type"),
                "content": att.get("content"),
                "inline": bool(att.get("inline", False)),
            }
        try:
            f = att
            f.seek(0)
            raw = f.read()
            if isinstance(raw, str):
                raw = raw.encode()
            content_b64 = base64.b64encode(raw).decode("ascii")
            return {
                "file_name": getattr(f, "name", "attachment"),
                "content_type": getattr(f, "content_type", None),
                "content": content_b64,
                "inline": False,
            }
        except Exception as e:
            logger.exception("attachment encode failed: %s", e)
            raise

    @staticmethod
    def send_email(
        subject: str,
        message: str,
        to: Union[str, Iterable[str], Iterable[dict]],
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        html_message: Optional[str] = None,
        attachments: Optional[Iterable[Any]] = None,
        headers: Optional[dict] = None,
        tags: Optional[dict] = None,
        timeout: int = 10,
    ) -> dict:
        if not MAILEROO_API_KEY:
            return {"success": False, "status_code": None, "body": None, "error": "MAILEROO_API_KEY not configured"}

        # Build sender address safely. Use verified sender domain only for from address, not for API URL.
        sender_addr = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None) or (f"no-reply@{MAILEROO_SENDER_DOMAIN}" if MAILEROO_SENDER_DOMAIN else None)
        if not sender_addr:
            return {"success": False, "status_code": None, "body": None, "error": "No sender address configured (DEFAULT_FROM_EMAIL or MAILEROO_SENDER_DOMAIN required)"}

        sender = {"address": sender_addr}
        if from_name:
            sender["display_name"] = from_name

        payload: dict = {
            "from": sender,
            "to": MailerooClient._normalize_recipients(to),
            "subject": subject,
            "plain": message,
        }
        if html_message:
            payload["html"] = html_message
        if headers:
            payload["headers"] = headers
        if tags:
            payload["tags"] = tags
        if attachments:
            encoded = []
            for att in attachments:
                try:
                    encoded.append(MailerooClient._encode_attachment(att))
                except Exception:
                    logger.warning("Skipping invalid attachment")
            if encoded:
                payload["attachments"] = encoded

        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MAILEROO_API_KEY}",
            "X-Api-Key": MAILEROO_API_KEY,
        }

        url = MAILEROO_RESOLVED_SEND_URL
        try:
            resp = requests.post(url, headers=req_headers, json=payload, timeout=timeout)
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            success = 200 <= resp.status_code < 300
            return {"success": success, "status_code": resp.status_code, "body": body, "error": None if success else f"HTTP {resp.status_code}"}
        except requests.exceptions.MissingSchema as ms:
            logger.exception("Maileroo send failed due to invalid URL (%s). Resolved URL=%s", ms, url)
            return {"success": False, "status_code": None, "body": None, "error": f"Invalid Maileroo URL: {url}"}
        except Exception as exc:
            logger.exception("Maileroo send_email exception: %s", exc)
            return {"success": False, "status_code": None, "body": None, "error": str(exc)}


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
    allow_smtp_fallback: bool = False,
    smtp_max_attempts: int = 3,
    smtp_backoff_seconds: float = 0.5,
    fail_silently: bool = False,
    attachments: Optional[Iterable[Any]] = None,
    **kwargs
) -> dict:
    results: Dict[str, dict] = {}
    if not recipient_list:
        return results

    for email in recipient_list:
        result: dict = {"sent": False, "attempts": 0, "verification": None, "reason": None, "error": None, "maileroo": None, "smtp": None}

        # Zeruh verification
        if verify_with_zeruh:
            verification = ZeruhEmailVerifier.verify(email)
            result["verification"] = verification
            if not verification or not verification.get("success"):
                result["reason"] = "Zeruh unavailable or error"
                if not allow_smtp_fallback:
                    results[email] = result
                    continue
            else:
                verdict = (verification.get("result") or {}) or {}
                status = verdict.get("status")
                score = int(verdict.get("score") or 0)
                if status not in ("deliverable", "risky") or score < zeruh_min_score:
                    result["reason"] = f"Zeruh verdict prevents send: status={status}, score={score}"
                    results[email] = result
                    continue

        # Maileroo primary sender
        if MAILEROO_API_KEY:
            last_err = None
            for attempt in range(1, maileroo_max_attempts + 1):
                result["attempts"] = attempt
                try:
                    resp = MailerooClient.send_email(
                        subject=subject,
                        message=message,
                        to=email,
                        from_email=from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None) or (f"no-reply@{MAILEROO_SENDER_DOMAIN}" if MAILEROO_SENDER_DOMAIN else None),
                        html_message=html_message,
                        attachments=attachments,
                        timeout=10,
                    )
                    result["maileroo"] = resp
                    if resp.get("success"):
                        result["sent"] = True
                        result["error"] = None
                        logger.info("Maileroo delivered to %s (attempt %d)", email, attempt)
                        break
                    else:
                        last_err = resp.get("error") or f"HTTP {resp.get('status_code')}"
                        logger.warning("Maileroo response for %s attempt %d: %s", email, attempt, last_err)
                except Exception as e:
                    last_err = str(e)
                    logger.exception("Maileroo exception for %s attempt %d: %s", email, attempt, e)

                time.sleep(maileroo_backoff_seconds * (2 ** (attempt - 1)))

            if not result["sent"]:
                result["reason"] = result.get("reason") or "Maileroo failed"
                result["error"] = last_err
        else:
            result["reason"] = "Maileroo not configured"

        # Optional SMTP fallback (explicit)
        if not result["sent"] and allow_smtp_fallback:
            last_err = None
            for attempt in range(1, smtp_max_attempts + 1):
                result["attempts"] = attempt
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
                    result["smtp"] = {"sent_count": sent_count}
                    if sent_count and sent_count > 0:
                        result["sent"] = True
                        logger.info("SMTP fallback delivered to %s (attempt %d)", email, attempt)
                        break
                    else:
                        last_err = "Email backend reported 0 delivered"
                        logger.warning("SMTP backend returned 0 for %s on attempt %d", email, attempt)
                except Exception as exc:
                    last_err = str(exc)
                    logger.exception("SMTP exception for %s attempt %d: %s", email, attempt, exc)
                    if fail_silently:
                        break
                time.sleep(smtp_backoff_seconds * (2 ** (attempt - 1)))
            if not result["sent"]:
                result["error"] = result.get("error") or last_err
                result["reason"] = result.get("reason") or "SMTP fallback failed"

        results[email] = result

    return results