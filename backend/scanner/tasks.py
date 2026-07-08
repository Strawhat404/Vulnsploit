import logging
from celery import shared_task, chain
from django.utils import timezone
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
        return f"Scan {scan_id} failed: {str(exc)}"


# ─── Full recon task ───────────────────────────────────────────────────────────

# Tools to run in order for a full recon
FULL_RECON_TOOLS = [
    'subfinder',      # passive recon first
    'whatweb',        # tech fingerprinting
    'testssl',        # SSL/TLS misconfiguration check
    'quick',          # fast nmap
    'nikto',          # web vulns
    'gobuster',       # directory brute-force
    'nuclei',         # template-based vulns
    'sqlmap',         # SQL injection
]


@shared_task(bind=True, max_retries=0)
def execute_full_recon(self, session_id):
    """
    Run all recon tools sequentially against a target.
    Updates ReconSession status as tools complete.
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

    for tool in FULL_RECON_TOOLS:
        # Create a ScanResult for this tool
        scan = ScanResult.objects.create(
            user          = session.user,
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
            failed_tools.append(tool)

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

        # Generate PDF
        pdf_path = render_pdf(report.id, target, interpreted, user)

        # Save report
        report.findings_json   = interpreted['findings']
        report.severity_counts = interpreted['severity_counts']
        report.risk_level      = interpreted['risk_level']
        report.pdf_file        = pdf_path
        report.status          = ScanReport.Status.READY
        report.generated_at    = timezone.now()
        report.save()

        logger.info("Report %s generated | target=%s findings=%d",
                    report.id, target, interpreted['total_findings'])
        return f"Report {report.id} generated"

    except Exception as exc:
        logger.error("Report generation failed | report=%s error=%s", report.id, str(exc))
        report.status        = ScanReport.Status.FAILED
        report.error_message = str(exc)
        report.save(update_fields=['status', 'error_message'])
        return f"Report {report.id} failed: {str(exc)}"
