"""
routers/v1/webhook.py — Simulated webhook consumer endpoint.

POST /api/v1/webhook/receive

This endpoint exists so developers and integration tests can verify the full
webhook delivery flow without running an external HTTP server.  It accepts the
signed payload, verifies the HMAC signature, and returns a 200 with the
delivery metadata.

The endpoint is unauthenticated — real webhook consumers receive from Watchdog,
they don't need to authenticate TO Watchdog.

Signature verification:
  1. Read X-Watchdog-Signature header: sha256=<hex>
  2. Compute HMAC-SHA256(body_bytes, secret)
  3. Compare with hmac.compare_digest (timing-safe)

Because this endpoint is a test stub, the secret used for verification is
passed as a query parameter (test_secret).  In production, the consumer would
have stored the secret at webhook registration time.
"""
import hashlib
import hmac
import logging

from fastapi import APIRouter, Header, Query, Request, status
from fastapi.responses import JSONResponse

from models.schemas.v1.webhook import WebhookReceiveResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhook", tags=["webhook-consumer"])


@router.post(
    "/receive",
    response_model=WebhookReceiveResponse,
    status_code=status.HTTP_200_OK,
)
async def receive_webhook(
    request: Request,
    test_secret: str = Query(
        default="",
        description="Webhook signing secret (for signature verification in tests)",
    ),
    x_watchdog_signature: str = Header(default="", alias="X-Watchdog-Signature"),
    x_watchdog_delivery_id: str = Header(default="", alias="X-Watchdog-Delivery-ID"),
    x_watchdog_event: str = Header(default="", alias="X-Watchdog-Event"),
) -> WebhookReceiveResponse:
    """
    Simulated consumer endpoint.  Accepts webhook deliveries and optionally
    verifies the HMAC signature when test_secret is provided.
    """
    body = await request.body()

    sig_valid = True
    if test_secret and x_watchdog_signature:
        expected_sig = "sha256=" + hmac.new(
            test_secret.encode(), body, hashlib.sha256
        ).hexdigest()
        sig_valid = hmac.compare_digest(expected_sig, x_watchdog_signature)

    logger.info(
        "webhook received",
        extra={
            "delivery_id": x_watchdog_delivery_id,
            "event": x_watchdog_event,
            "sig_valid": sig_valid,
            "body_bytes": len(body),
        },
    )

    if not sig_valid:
        return JSONResponse(
            {"error": "signature mismatch", "delivery_id": x_watchdog_delivery_id},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return WebhookReceiveResponse(
        received=True,
        delivery_id=x_watchdog_delivery_id,
        event_type=x_watchdog_event,
    )
