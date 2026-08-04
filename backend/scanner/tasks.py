import logging
import os
import threading
import concurrent.futures
from pathlib import Path
from celery import shared_task, chain
from django.utils import timezone
from django.core.files import File
from django.conf import settings
from .utils import run_scan
from .models import ScanResult, ReconSession

logger = logging.getLogger('scanner')


# ─── Single scan task ──────────────────────────────────────────────────────────

@shared_task(bind=True, max_retries=0)
def execute_scan(self, scan_id, target, scan_type):
    """Execute a single security scan and update status at each stage."""
    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        logger.error("execute_scan: scan %s not found", scan_id)
        return f"Scan {scan_id} not found"

    scan.status = ScanResult.Status.RUNNING
    scan.result = "Scan in progress..."
    scan.save(update_fields=['status', 'result'])

    logger.info("Scan %s started | target=%s type=%s", scan_id, target, scan_type)

    try:
        result_text, result_json = run_scan(scan.target, scan.scan_type)

        scan.status       = ScanResult.Status.COMPLETED
        scan.result       = result_text
        scan.result_json  = result_json
        scan.completed_at = timezone.now()
        scan.save(update_fields=['status', 'result', 'result_json', 'completed_at'])

        logger.info("Scan %s completed | target=%s", scan_id, target)

        from .notifications import send_scan_complete_email
        send_scan_complete_email(scan.user, scan)

        return f"Scan {scan_id} completed"

    except Exception as exc:
        logger.error("Scan %s failed | error=%s", scan_id, str(exc))
        try:
            scan.status       = ScanResult.Status.FAILED
            scan.result       = f"Error: {str(exc)}"
            scan.completed_at = timezone.now()
            scan.save(update_fields=['status', 'result', 'completed_at'])
        except Exception:
            pass

        from .notifications import send_scan_complete_email
        send_scan_complete_email(scan.user, scan)

        return f"Scan {scan_id} failed: {str(exc)}"


# ─── Full recon task ───────────────────────────────────────────────────────────

# Tools to run in order for a full recon
FULL_RECON_TOOLS = [
    'subfinder',      # passive recon first
    'whatweb',        # tech fingerprinting
    'testssl',        # SSL/TLS misconfiguration check
    'headers',        # HTTP security headers check
    'quick',          # fast nmap
    'nikto',          # web vulns
    'gobuster',       # directory brute-force
    'nuclei',         # template-based vulns
    'sqlmap',         # SQL injection
]


@shared_task(bind=True, max_retries=0)
def execute_full_recon(self, session_id):
    """
    Run all recon tools in parallel against a target.
    Uses ThreadPoolExecutor for concurrent tool execution.
    """
    try:
        session = ReconSession.objects.get(id=session_id)
    except ReconSession.DoesNotExist:
        logger.error("execute_full_recon: session %s not found", session_id)
        return

    session.status = ReconSession.Status.RUNNING
    session.save(update_fields=['status'])

    logger.info("Full recon started | session=%s target=%s", session_id, session.target)

    failed_tools = []
    lock = threading.Lock()

    def run_tool(tool):
        scan = ScanResult.objects.create(
            user          = session.user,
            organization = session.organization_id,
            target        = session.target,
            scan_type     = tool,
            status        = ScanResult.Status.RUNNING,
            result        = f"Running {tool}...",
            recon_session = session,
        )

        logger.info("Full recon | session=%s running tool=%s", session_id, tool)

        try:
            result_text, result_json = run_scan(session.target, tool)

            scan.status       = ScanResult.Status.COMPLETED
            scan.result       = result_text
            scan.result_json  = result_json
            scan.completed_at = timezone.now()
            scan.save(update_fields=['status', 'result', 'result_json', 'completed_at'])

            logger.info("Full recon | session=%s tool=%s done", session_id, tool)

        except Exception as exc:
            logger.error("Full recon | session=%s tool=%s failed: %s", session_id, tool, str(exc))
            scan.status       = ScanResult.Status.FAILED
            scan.result       = f"Error: {str(exc)}"
            scan.completed_at = timezone.now()
            scan.save(update_fields=['status', 'result', 'completed_at'])
            with lock:
                failed_tools.append(tool)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(FULL_RECON_TOOLS)) as executor:
        list(executor.map(run_tool, FULL_RECON_TOOLS))

    # Mark session complete
    session.status       = ReconSession.Status.COMPLETED
    session.completed_at = timezone.now()
    session.save(update_fields=['status', 'completed_at'])

    logger.info(
        "Full recon completed | session=%s target=%s failed_tools=%s",
        session_id, session.target, failed_tools
    )

    # Auto-generate report
    generate_report.delay(session_id=session_id)

    return f"Full recon session {session_id} completed"


# ─── Scheduled scan entry point (driven by django-celery-beat) ─────────────────

@shared_task(bind=True, max_retries=0)
def run_scheduled_scan(self, scheduled_scan_id):
    """
    Triggered by Celery Beat from a ScheduledScan row. Creates a fresh
    pending ScanResult and delegates to execute_scan, then updates the
    ScheduledScan's last_run_at / next_run_at bookkeeping.
    """
    from .models import ScheduledScan, ScanResult

    try:
        scheduled = ScheduledScan.objects.get(id=scheduled_scan_id)
    except ScheduledScan.DoesNotExist:
        logger.warning("run_scheduled_scan: ScheduledScan %s missing", scheduled_scan_id)
        return

    if not scheduled.is_active:
        logger.info("run_scheduled_scan: %s is inactive — skipping", scheduled_scan_id)
        return

    scan = ScanResult.objects.create(
        user          = scheduled.user,
        organization  = scheduled.organization_id,
        target        = scheduled.target,
        scan_type     = scheduled.scan_type,
        status        = ScanResult.Status.PENDING,
        result        = "Scan queued (scheduled)...",
    )
    task = execute_scan.delay(scan.id, scheduled.target, scheduled.scan_type)
    scan.celery_task_id = task.id
    scan.save(update_fields=['celery_task_id'])

    scheduled.last_run_at = timezone.now()
    scheduled.save(update_fields=['last_run_at'])

    logger.info("Scheduled scan fired | scheduled_scan=%s scan=%s target=%s",
                scheduled_scan_id, scan.id, scheduled.target)


# ─── Report generation task ────────────────────────────────────────────────────

@shared_task(bind=True, max_retries=0)
def generate_report(self, session_id=None, scan_ids=None, report_id=None):
    """
    Generate a PDF report from a ReconSession or a list of ScanResult IDs.
    If report_id is provided, update that existing report record.
    """
    from .models import ScanReport
    from .parsers import parse_scan_result
    from .ai_interpreter import interpret_all_scans
    from .report_generator import render_pdf

    # Resolve which scans to include
    if session_id:
        try:
            session = ReconSession.objects.get(id=session_id)
        except ReconSession.DoesNotExist:
            logger.error("generate_report: session %s not found", session_id)
            return

        scans  = session.scan_results.filter(status='completed')
        target = session.target
        user   = session.user

        # Get or create report record
        report, _ = ScanReport.objects.get_or_create(
            recon_session=session,
            defaults={'user': user, 'target': target, 'status': ScanReport.Status.GENERATING}
        )

    elif scan_ids:
        scans  = ScanResult.objects.filter(id__in=scan_ids, status='completed')
        target = scans.first().target if scans.exists() else 'Unknown'
        user   = scans.first().user   if scans.exists() else None

        if report_id:
            try:
                report = ScanReport.objects.get(id=report_id)
            except ScanReport.DoesNotExist:
                logger.error("generate_report: report %s not found", report_id)
                return
        else:
            report = ScanReport.objects.create(
                user=user, target=target, status=ScanReport.Status.GENERATING
            )
            report.scan_results.set(scans)
    else:
        logger.error("generate_report: no session_id or scan_ids provided")
        return

    report.status = ScanReport.Status.GENERATING
    report.save(update_fields=['status'])

    logger.info("Generating report | report=%s target=%s", report.id, target)

    try:
        # Parse all scan results
        scan_data = []
        for scan in scans:
            parsed = parse_scan_result(scan.scan_type, scan.result, scan.result_json)
            scan_data.append({
                'scan_type':   scan.scan_type,
                'parsed_data': parsed,
                'scan_id':     scan.id,
            })

        # ── CVE enrichment — query NVD for known CVEs on detected software ──
        from .cve_enricher import enrich_with_cves
        cve_data = enrich_with_cves(scan_data)

        # AI interpret all findings
        interpreted = interpret_all_scans(scan_data, target)

        # Merge CVE findings into interpreted findings (CVEs go first by severity)
        if cve_data.get('findings'):
            interpreted['findings'] = cve_data['findings'] + interpreted['findings']
            # Re-sort all findings by severity
            SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            interpreted['findings'].sort(
                key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'info'), 5)
            )
            # Update severity counts
            for f in cve_data['findings']:
                sev = f.get('severity', 'info').lower()
                if sev in interpreted['severity_counts']:
                    interpreted['severity_counts'][sev] += 1
            interpreted['total_findings'] = len(interpreted['findings'])

        # Store CVE component data for the PDF report table
        interpreted['cve_components'] = cve_data.get('components', [])
        interpreted['total_cves']     = cve_data.get('total_cves', 0)

        # ── Deduplication — merge overlapping findings from multiple tools ──
        from .dedup import deduplicate_findings
        deduped, dedup_stats = deduplicate_findings(interpreted['findings'])
        interpreted['findings'] = deduped
        interpreted['dedup_stats'] = dedup_stats

        # ── Suppression — apply false-positive / accepted-risk decisions ──
        from .suppression import apply_suppressions
        suppression_stats = apply_suppressions(interpreted['findings'], target)
        interpreted['suppression_stats'] = suppression_stats

        # Recalculate severity counts after dedup + suppression
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in deduped:
            if f.get('suppression') in ('false_positive',):
                continue  # Don't count false positives in severity totals
            sev = f.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        interpreted['severity_counts'] = severity_counts
        interpreted['total_findings'] = len(deduped)

        # ── Compliance mapping — tag findings with OWASP + CWE categories ──
        from .compliance import enrich_findings_with_compliance, get_compliance_summary
        enrich_findings_with_compliance(interpreted['findings'])
        interpreted['compliance_summary'] = get_compliance_summary(interpreted['findings'])

        # ── Security posture score (0-100, higher = better) ──
        from .posture import calculate_posture_score
        interpreted['posture_score'] = calculate_posture_score(
            interpreted['severity_counts'],
            interpreted['total_findings'],
        )

        # Generate PDF (writes to MEDIA_ROOT/reports/<filename> locally)
        pdf_rel_path = render_pdf(report.id, target, interpreted, user, scans)

        # Persist the PDF via the configured storage backend. Using
        # FileField.save() ensures the file is uploaded to S3/R2 when
        # django-storages is configured, and simply copied in place when
        # using the default local filesystem storage.
        local_pdf_path = os.path.join(settings.MEDIA_ROOT, pdf_rel_path)
        filename       = Path(pdf_rel_path).name
        with open(local_pdf_path, 'rb') as f:
            report.pdf_file.save(filename, File(f), save=False)

        # If we are using a remote object store (S3/R2), remove the local
        # copy to keep the ephemeral filesystem small.
        _remote_storage = 'S3Storage' in getattr(
            settings, 'STORAGES', {}).get('default', {}).get('BACKEND', '')
        if _remote_storage:
            try:
                os.remove(local_pdf_path)
            except OSError:
                pass

        # Save report
        report.findings_json   = interpreted['findings']
        report.severity_counts = interpreted['severity_counts']
        report.risk_level      = interpreted['risk_level']
        report.status          = ScanReport.Status.READY
        report.generated_at    = timezone.now()
        report.save()

        logger.info("Report %s generated | target=%s findings=%d",
                    report.id, target, interpreted['total_findings'])

        from .notifications import send_report_ready_email, send_webhook_alerts
        send_report_ready_email(user, report)
        send_webhook_alerts(user, 'report.ready', {
            'target': target, 'report_id': report.id,
            'risk_level': report.risk_level,
        })

        # ── Change detection: compare with previous report for same target ──
        prev_report = ScanReport.objects.filter(
            target=target,
            status='ready',
        ).exclude(id=report.id).order_by('-generated_at').first()

        if prev_report and prev_report.findings_json:
            from .diff import compare_reports
            from .posture import calculate_posture_score

            diff = compare_reports(
                prev_report.findings_json or [],
                report.findings_json or [],
            )

            # Alert on new critical findings
            if diff['new_critical_count'] > 0:
                send_webhook_alerts(user, 'finding.new_critical', {
                    'target': target,
                    'report_id': report.id,
                    'count': diff['new_critical_count'],
                    'findings': diff['new_findings'][:10],
                })
                logger.warning(
                    "Change detection: %d new CRITICAL findings on %s",
                    diff['new_critical_count'], target,
                )

            # Alert on new high findings
            if diff['new_high_count'] > 0:
                send_webhook_alerts(user, 'finding.new_high', {
                    'target': target,
                    'report_id': report.id,
                    'count': diff['new_high_count'],
                    'findings': diff['new_findings'][:10],
                })

            # Alert on posture score change
            old_score = calculate_posture_score(
                prev_report.severity_counts or {},
                len(prev_report.findings_json or []),
            )
            new_score = interpreted['posture_score']
            if old_score != new_score:
                send_webhook_alerts(user, 'posture.changed', {
                    'target': target,
                    'report_id': report.id,
                    'old_score': old_score,
                    'new_score': new_score,
                })

            logger.info(
                "Change detection: %s | new=%d resolved=%d unchanged=%d posture %d→%d",
                target, len(diff['new_findings']),
                len(diff['resolved_findings']),
                len(diff['unchanged_findings']),
                old_score, new_score,
            )

        return f"Report {report.id} generated"

    except Exception as exc:
        logger.error("Report generation failed | report=%s error=%s", report.id, str(exc))
        report.status        = ScanReport.Status.FAILED
        report.error_message = str(exc)
        report.save(update_fields=['status', 'error_message'])
        return f"Report {report.id} failed: {str(exc)}"
