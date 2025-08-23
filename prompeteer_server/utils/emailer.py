import os
import requests
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
import logging

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

        params = {"email_address": email, "timeout": timeout}
        if ip_address:
            params["ip_address"] = ip_address

        try:
            resp = requests.get(
                f"{ZERUH_BASE_URL}/verify",
                params=params,
                headers={"X-Api-Key": ZERUH_API_KEY},
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
                headers={"X-Api-Key": ZERUH_API_KEY},
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
    recipient_list,
    from_email=None,
    html_message=None,
    verify_with_zeruh=True,
    zeruh_min_score=70,
    fail_silently=False,
    **kwargs
):
    """
    Send an email after verifying recipients with Zeruh.
    Only sends to emails that are 'deliverable' or 'risky' with score >= zeruh_min_score.
    Returns a dict with results for each recipient.
    """
    results = {}
    for email in recipient_list:
        if verify_with_zeruh:
            verification = ZeruhEmailVerifier.verify(email)
            if not verification or not verification.get("success"):
                results[email] = {"sent": False, "reason": "Zeruh error"}
                continue
            result = verification.get("result", {})
            status = result.get("status")
            score = result.get("score", 0)
            if status not in ("deliverable", "risky") or score < zeruh_min_score:
                results[email] = {
                    "sent": False,
                    "reason": f"Zeruh status={status}, score={score}"
                }
                continue
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email or settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                html_message=html_message,
                fail_silently=fail_silently,
            )
            results[email] = {"sent": True}
        except Exception as e:
            logger.error(f"Failed to send email to {email}: {e}")
            results[email] = {"sent": False, "reason": str(e)}
    return results