"""Small, dependency-free Dodo Payments client and webhook verifier."""

import base64
import hashlib
import hmac
import json
import os
import time

import requests


class DodoBillingError(RuntimeError):
    pass


def environment():
    value = os.environ.get("DODO_PAYMENTS_ENVIRONMENT", "test_mode").strip().lower()
    return "live_mode" if value in {"live", "live_mode"} else "test_mode"


def api_key():
    if environment() == "test_mode":
        return os.environ.get("DODO_PAYMENTS_TEST_API_KEY", "").strip()
    return os.environ.get("DODO_PAYMENTS_API_KEY", "").strip()


def api_base():
    return "https://live.dodopayments.com" if environment() == "live_mode" else "https://test.dodopayments.com"


def configured():
    return bool(api_key())


def create_checkout(*, product_id, user_id, email, name, return_url, cancel_url, plan):
    if not configured():
        raise DodoBillingError("Dodo Payments is not configured")
    if not product_id:
        raise DodoBillingError("The Dodo product ID for this plan is not configured")
    payload = {
        "product_cart": [{"product_id": product_id, "quantity": 1}],
        "customer": {"email": email, "name": name},
        "return_url": return_url,
        "cancel_url": cancel_url,
        "metadata": {"arlong_user_id": str(user_id), "arlong_plan": plan},
    }
    try:
        response = requests.post(
            f"{api_base()}/checkouts",
            headers={"Authorization": f"Bearer {api_key()}", "Content-Type": "application/json"},
            json=payload,
            timeout=20,
        )
    except requests.RequestException as exc:
        raise DodoBillingError("Could not reach Dodo Payments") from exc
    if not response.ok:
        try:
            detail = response.json().get("message") or response.json().get("error")
        except (ValueError, AttributeError):
            detail = None
        raise DodoBillingError(detail or f"Dodo checkout failed (HTTP {response.status_code})")
    body = response.json()
    if not body.get("checkout_url"):
        raise DodoBillingError("Dodo did not return a checkout URL")
    return body


def create_customer_portal(customer_id, return_url):
    if not configured() or not customer_id:
        raise DodoBillingError("No Dodo customer is connected to this account")
    try:
        response = requests.post(
            f"{api_base()}/customers/{customer_id}/customer-portal/session",
            headers={"Authorization": f"Bearer {api_key()}"},
            params={"return_url": return_url},
            timeout=20,
        )
    except requests.RequestException as exc:
        raise DodoBillingError("Could not reach Dodo Payments") from exc
    if not response.ok:
        raise DodoBillingError(f"Could not open the billing portal (HTTP {response.status_code})")
    link = response.json().get("link")
    if not link:
        raise DodoBillingError("Dodo did not return a customer portal link")
    return link


def _secret_bytes(secret):
    # Standard Webhooks secrets are commonly prefixed with whsec_.
    raw = secret[6:] if secret.startswith("whsec_") else secret
    try:
        return base64.b64decode(raw, validate=True)
    except Exception:
        return raw.encode("utf-8")


def verify_webhook(raw_body, headers, *, tolerance_seconds=300):
    """Verify a Standard Webhooks HMAC signature and return parsed JSON."""
    secret_name = "DODO_PAYMENTS_LIVE_WEBHOOK_SECRET" if environment() == "live_mode" else "DODO_PAYMENTS_WEBHOOK_SECRET"
    secret = (os.environ.get(secret_name) or
              os.environ.get("DODO_PAYMENTS_WEBHOOK_KEY", "")).strip()
    if not secret:
        raise DodoBillingError("Webhook secret is not configured")
    webhook_id = headers.get("webhook-id", "")
    timestamp = headers.get("webhook-timestamp", "")
    signatures = headers.get("webhook-signature", "")
    if not webhook_id or not timestamp or not signatures:
        raise DodoBillingError("Missing webhook signature headers")
    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        raise DodoBillingError("Invalid webhook timestamp") from exc
    if abs(int(time.time()) - sent_at) > tolerance_seconds:
        raise DodoBillingError("Webhook timestamp is outside the allowed window")
    payload_text = raw_body.decode("utf-8")
    signed = f"{webhook_id}.{timestamp}.{payload_text}".encode("utf-8")
    expected = base64.b64encode(hmac.new(_secret_bytes(secret), signed, hashlib.sha256).digest()).decode()
    candidates = []
    for item in signatures.replace(" ", ",").split(","):
        item = item.strip()
        if not item:
            continue
        candidates.append(item.split("=", 1)[-1] if "=" in item and item.startswith("v") else item)
    if not any(hmac.compare_digest(expected, candidate) for candidate in candidates):
        raise DodoBillingError("Invalid webhook signature")
    try:
        return json.loads(payload_text)
    except ValueError as exc:
        raise DodoBillingError("Invalid webhook JSON") from exc
