import os
import time
import base64
import logging
from typing import Iterable, Optional, Union, List, Dict, Any, Tuple

import requests

from django.conf import settings
from django.core.mail import EmailMessage, get_connection

logger = logging.getLogger("emailer")

# Zeruh
ZERUH_API_KEY = os.environ.get("ZERUH_API_KEY") or getattr(settings, "ZERUH_API_KEY", None)
ZERUH_BASE_URL = getattr(settings, "ZERUH_BASE_URL", "https://api.zeruh.com/v1")

# Maileroo configuration
MAILEROO_API_KEY = os.environ.get("MAILEROO_API_KEY") or getattr(settings, "MAILEROO_API_KEY", None)
MAILEROO_API_BASE_URL = os.environ.get("MAILEROO_API_BASE_URL") or getattr(settings, "MAILEROO_API_BASE_URL", "https://smtp.maileroo.com/api/v2/")
MAILEROO_SEND_URL = os.environ.get("MAILEROO_SEND_URL") or getattr(settings, "MAILEROO_SEND_URL", None)
MAILEROO_SENDER_DOMAIN = os.environ.get("MAILEROO_SENDER_DOMAIN") or getattr(settings, "MAILEROO_SENDER_DOMAIN", None)


def _resolve_maileroo_send_url() -> str:
    if MAILEROO_SEND_URL:
        if MAILEROO_SEND_URL.lower().startswith("http://") or MAILEROO_SEND_URL.lower().startswith("https://"):
            return MAILEROO_SEND_URL
        logger.warning("MAILEROO_SEND_URL missing scheme; falling back to base URL")
    base = MAILEROO_API_BASE_URL.rstrip("/")
    return f"{base}/emails"


MAILEROO_RESOLVED_SEND_URL = _resolve_maileroo_send_url()


class ZeruhEmailVerifier:
    @staticmethod
    def verify(email: str, ip_address: Optional[str] = None, timeout: int = 10) -> Optional[dict]:
        if not ZERUH_API_KEY:
            logger.debug("Zeruh API key not configured.")
            return None
        params = {"email_address": email, "api_key": ZERUH_API_KEY}
        if ip_address:
            params["ip_address"] = ip_address
        try:
            resp = requests.get(f"{ZERUH_BASE_URL}/verify", params=params, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("Zeruh verify failed for %s: %s", email, exc)
            return None


class BaseEmailProvider:
    name = "base"

    def send(self, subject: str, message: str, to: List[str], from_email: Optional[str] = None,
             html_message: Optional[str] = None, attachments: Optional[Iterable[Any]] = None,
             timeout: int = 10, **kwargs) -> dict:
        raise NotImplementedError()


class DjangoSMTPProvider(BaseEmailProvider):
    name = "django"

    def send(self, subject: str, message: str, to: List[str], from_email: Optional[str] = None,
             html_message: Optional[str] = None, attachments: Optional[Iterable[Any]] = None,
             timeout: int = 10, fail_silently: bool = False, **kwargs) -> dict:
        conn = None
        try:
            conn = get_connection(fail_silently=fail_silently)
            msg = EmailMessage(subject=subject, body=message,
                               from_email=from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None),
                               to=to, connection=conn)
            if html_message:
                msg.content_subtype = "html"
                msg.body = html_message
            if attachments:
                for att in attachments:
                    # attachments can be tuples (path, filename, mimetype) or file-like
                    try:
                        if isinstance(att, tuple) and len(att) >= 2:
                            path_or_obj, name = att[0], att[1]
                            if hasattr(path_or_obj, "read"):
                                msg.attach(name, path_or_obj.read(), att[2] if len(att) > 2 else None)
                            else:
                                with open(path_or_obj, "rb") as f:
                                    msg.attach(name, f.read(), att[2] if len(att) > 2 else None)
                        else:
                            # file-like
                            if hasattr(att, "read"):
                                name = getattr(att, "name", "attachment")
                                msg.attach(name, att.read())
                    except Exception as e:
                        logger.exception("Failed to attach file for DjangoSMTPProvider: %s", e)
            sent = msg.send(fail_silently=fail_silently)
            return {"success": bool(sent), "provider": self.name, "sent_count": sent}
        except Exception as exc:
            logger.exception("DjangoSMTPProvider send failed: %s", exc)
            return {"success": False, "provider": self.name, "error": str(exc)}


class MailerooProvider(BaseEmailProvider):
    name = "maileroo"

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

    def send(self, subject: str, message: str, to: List[str], from_email: Optional[str] = None,
             html_message: Optional[str] = None, attachments: Optional[Iterable[Any]] = None,
             timeout: int = 10, **kwargs) -> dict:
        if not MAILEROO_API_KEY:
            return {"success": False, "provider": self.name, "error": "MAILEROO_API_KEY not configured"}

        sender_addr = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None) or (f"no-reply@{MAILEROO_SENDER_DOMAIN}" if MAILEROO_SENDER_DOMAIN else None)
        if not sender_addr:
            return {"success": False, "provider": self.name, "error": "No sender address configured"}

        sender = {"address": sender_addr}
        payload: dict = {
            "from": sender,
            "to": self._normalize_recipients(to),
            "subject": subject,
            "plain": message,
        }
        if html_message:
            payload["html"] = html_message
        if attachments:
            encoded = []
            for att in attachments:
                try:
                    encoded.append(self._encode_attachment(att))
                except Exception:
                    logger.warning("Skipping invalid attachment")
            if encoded:
                payload["attachments"] = encoded

        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MAILEROO_API_KEY}",
            "X-Api-Key": MAILEROO_API_KEY,
        }
        try:
            resp = requests.post(MAILEROO_RESOLVED_SEND_URL, headers=req_headers, json=payload, timeout=timeout)
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            success = 200 <= resp.status_code < 300
            return {"success": success, "provider": self.name, "status_code": resp.status_code, "body": body, "error": None if success else f"HTTP {resp.status_code}"}
        except Exception as exc:
            logger.exception("MailerooProvider send failed: %s", exc)
            return {"success": False, "provider": self.name, "error": str(exc)}


DEFAULT_PROVIDER_ORDER = getattr(settings, "EMAIL_PROVIDER_ORDER", ["django", "maileroo"])  # first wins


PROVIDERS: Dict[str, BaseEmailProvider] = {
    "django": DjangoSMTPProvider(),
    "maileroo": MailerooProvider(),
}


def _ensure_list_of_strings(x: Union[str, Iterable[str], None]) -> List[str]:
    if not x:
        return []
    if isinstance(x, str):
        return [x]
    return list(x)


def send_verified_email(
    subject: str,
    message: str,
    recipient_list: Iterable[str],
    from_email: Optional[str] = None,
    html_message: Optional[str] = None,
    verify_with_zeruh: bool = True,
    zeruh_min_score: int = 10,
    provider_order: Optional[List[str]] = None,
    allow_smtp_primary: bool = True,
    fail_silently: bool = False,
    attachments: Optional[Iterable[Any]] = None,
    timeout: int = 10,
    **kwargs,
) -> Dict[str, dict]:
    """
    High-level email send function.
    Flow:
      - For each recipient: optionally verify via Zeruh.
      - Try providers in order (default: Django SMTP then Maileroo). Stop when one succeeds per recipient.

    Returns mapping recipient -> result dict with keys: sent (bool), provider, error, verification.
    """
    results: Dict[str, dict] = {}
    if not recipient_list:
        return results

    recipients = _ensure_list_of_strings(recipient_list)
    order = provider_order or DEFAULT_PROVIDER_ORDER

    for email in recipients:
        res: Dict[str, Any] = {"sent": False, "provider": None, "error": None, "verification": None}

        # Zeruh verification (if requested)
        if verify_with_zeruh:
            verification = ZeruhEmailVerifier.verify(email, timeout=timeout)
            res["verification"] = verification
            if verification and verification.get("success"):
                verdict = (verification.get("result") or {})
                status = verdict.get("status")
                score = int(verdict.get("score") or 0)
                if status not in ("deliverable", "risky") or score < zeruh_min_score:
                    res.update({"sent": False, "error": f"Zeruh blocked send: status={status}, score={score}"})
                    results[email] = res
                    continue
            else:
                # If Zeruh is unavailable, be permissive but record verification=None
                res["verification"] = verification

        # Try providers in order
        last_err = None
        for provider_name in order:
            provider = PROVIDERS.get(provider_name)
            if not provider:
                continue
            try:
                r = provider.send(subject=subject, message=message, to=[email], from_email=from_email,
                                  html_message=html_message, attachments=attachments, timeout=timeout,
                                  fail_silently=fail_silently)
                res.update({"provider": provider_name, "attempt_result": r})
                if r.get("success"):
                    res["sent"] = True
                    res["error"] = None
                    break
                else:
                    last_err = r.get("error") or r.get("body")
                    res["error"] = last_err
            except Exception as exc:
                last_err = str(exc)
                res["error"] = last_err
        results[email] = res

    return results


def send_otp_email(email: str, otp: str, subject: Optional[str] = None, html_template: Optional[str] = None,
                   provider_order: Optional[List[str]] = None, **kwargs) -> Dict[str, dict]:
    """Convenience helper for sending OTP/auth emails to a single recipient.
    otp: numeric or string OTP value. The function builds a simple message body; callers can pass html_template to override.
    """
    subject = subject or getattr(settings, "OTP_EMAIL_SUBJECT", "Your verification code")
    if html_template:
        html_message = html_template.replace("{{OTP}}", str(otp))
        message = f"Your verification code is: {otp}"  # fallback plain text
    else:
        html_message = None
        message = f"Your verification code is: {otp}"
    return send_verified_email(subject=subject, message=message, recipient_list=[email], html_message=html_message,
                               provider_order=provider_order, **kwargs)
