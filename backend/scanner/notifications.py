import logging
from django.conf import settings
from django.core.mail import send_mail
from .models import UserProfile

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
