import logging
import json
import hmac
import hashlib
from django.conf import settings
from django.core.mail import send_mail
from django.db import models as dj_models
from django.utils import timezone
import requests as http_requests

from .models import UserProfile, WebhookEndpoint
from .netguard import UnsafeTarget, assert_public_url

logger = logging.getLogger('scanner')


def _should_notify(user, preference):
    profile = UserProfile.objects.filter(user=user).first()
    if not profile:
        return True
    return getattr(profile, preference, True)


def send_scan_complete_email(user, scan):
    if not _should_notify(user, 'notify_scan_complete'):
        return
    if not user.email:
        return

    subject = f"[VulnSploit] Scan Complete — {scan.target}"
    message = (
        f"Scan {scan.id} on {scan.target} ({scan.scan_type}) is now {scan.status}.\n\n"
        f"View result: {settings.SITE_URL}/scans/{scan.id}"
    )

    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
        logger.info("Notification sent to %s for scan %s", user.email, scan.id)
    except Exception as e:
        logger.warning("Failed to send email to %s: %s", user.email, str(e))


def send_report_ready_email(user, report):
    if not _should_notify(user, 'notify_report_ready'):
        return
    if not user.email:
        return

    subject = f"[VulnSploit] Report Ready — {report.target}"
    message = (
        f"Report {report.id} for {report.target} is ready.\n"
        f"Risk level: {report.risk_level}\n\n"
        f"View report: {settings.SITE_URL}/reports/{report.id}"
    )

    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
        logger.info("Notification sent to %s for report %s", user.email, report.id)
    except Exception as e:
        logger.warning("Failed to send email to %s: %s", user.email, str(e))


def send_verification_expiry_email(target, recipients, days_left):
    """Warn that a target's ownership verification is about to lapse (or has)."""
    if days_left <= 0:
        subject = f"[VulnSploit] Verification expired — {target.value}"
        lead = (f"Ownership verification for {target.value} has expired. Scans and "
                f"schedules for it are now blocked.")
    else:
        subject = (f"[VulnSploit] Verification expires in {days_left} "
                   f"{'day' if days_left == 1 else 'days'} — {target.value}")
        unit = 'day' if days_left == 1 else 'days'
        lead = (f"Ownership verification for {target.value} will expire in "
                f"{days_left} {unit}. After that, scans and schedules for it will be blocked.")
    message = (
        f"{lead}\n\n"
        f"To renew, open Targets and press Verify again. If the DNS record or file "
        f"is still in place it succeeds immediately.\n\n"
        f"{settings.SITE_URL}/targets"
    )
    try:
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, list(recipients), fail_silently=True)
        logger.info("Verification expiry notice sent for target %s (%s days) to %d recipient(s)",
                    target.id, days_left, len(recipients))
    except Exception as e:
        logger.warning("Failed to send expiry notice for target %s: %s", target.id, str(e))


# ─── Webhook delivery ──────────────────────────────────────────────────────────

def _get_user_orgs_qs(user):
    """Return the queryset of Org IDs the user belongs to."""
    from .models import Organization
    return Organization.objects.filter(memberships__user=user).values_list('id', flat=True)


def _deliver_webhook(webhook, event, payload):
    """
    Deliver a single webhook with HMAC signature.
    The signature is placed in X-VulnSploit-Signature as hex sha256.
    """
    body = json.dumps({
        'event':  event,
        'payload': payload,
    })

    signature = hmac.new(
        webhook.secret.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()

    headers = {
        'Content-Type':           'application/json',
        'X-VulnSploit-Signature': f'sha256={signature}',
        'X-VulnSploit-Event':     event,
        'User-Agent':             'VulnSploit/1.0',
    }

    # Slack-compatible format: if the URL is a Slack webhook, wrap in
    # their required { "text": "..." } envelope. Otherwise send raw JSON.
    if 'hooks.slack.com' in webhook.url:
        body = json.dumps({'text': _format_slack_message(event, payload)})
    elif 'discord.com/api/webhooks' in webhook.url:
        body = json.dumps({'content': _format_slack_message(event, payload)})

    # The URL was validated when saved, but DNS may have changed since.
    try:
        assert_public_url(webhook.url)
    except UnsafeTarget as exc:
        logger.warning("Webhook %s skipped, unsafe URL: %s", webhook.id, str(exc))
        return

    try:
        resp = http_requests.post(
            webhook.url, data=body, headers=headers, timeout=10,
            allow_redirects=False,  # a redirect could bounce us to an internal host
        )
        if resp.status_code in (200, 204):
            logger.info("Webhook %s delivered: %s (HTTP %s)", webhook.id, event, resp.status_code)
        else:
            logger.warning("Webhook %s returned %s for event %s", webhook.id, resp.status_code, event)
    except Exception as e:
        logger.warning("Webhook %s delivery failed: %s", webhook.id, str(e))

    webhook.last_triggered_at = timezone.now()
    webhook.save(update_fields=['last_triggered_at'])


def _format_slack_message(event, payload):
    """Format a human-readable alert message for Slack/Discord."""
    if event == 'finding.new_critical':
        return (
            f":rotating_light: *{payload.get('count', 0)} new CRITICAL findings* detected "
            f"on `{payload.get('target', '?')}`.\n"
            f"Report: {settings.SITE_URL}/reports/{payload.get('report_id', '')}"
        )
    elif event == 'finding.new_high':
        return (
            f":warning: *{payload.get('count', 0)} new HIGH findings* detected "
            f"on `{payload.get('target', '?')}`.\n"
            f"Report: {settings.SITE_URL}/reports/{payload.get('report_id', '')}"
        )
    elif event == 'posture.changed':
        return (
            f":chart_with_downwards_trend: Security posture changed for "
            f"`{payload.get('target', '?')}`: "
            f"{payload.get('old_score', '?')} → {payload.get('new_score', '?')}"
        )
    elif event == 'report.ready':
        return (
            f":page_facing_up: Report ready for `{payload.get('target', '?')}` "
            f"(risk: {payload.get('risk_level', '?')})\n"
            f"View: {settings.SITE_URL}/reports/{payload.get('report_id', '')}"
        )
    return f"VulnSploit alert: {event}"


def send_webhook_alerts(user, event, payload):
    """
    Fire webhooks that are subscribed to the given event.
    Finds all active webhooks owned by the user (or their orgs) that
    list 'event' in their events array.
    """
    user_orgs = list(_get_user_orgs_qs(user))
    webhooks = WebhookEndpoint.objects.filter(
        is_active=True,
    ).filter(
        dj_models.Q(organization__id__in=user_orgs) |
        dj_models.Q(organization__isnull=True, user=user),
    )

    delivered = 0
    for wh in webhooks:
        if event in (wh.events or []):
            _deliver_webhook(wh, event, payload)
            delivered += 1

    if delivered:
        logger.info("Delivered %d webhooks for event %s", delivered, event)
    return delivered
