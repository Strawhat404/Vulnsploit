"""
Report comparison / diff engine.
Compares two ScanReport findings_json arrays and identifies:
- new_findings: present in the newer report but not the older
- resolved_findings: present in the older report but not the newer
- unchanged_findings: present in both

Findings are matched by a fingerprint hash of (title, severity, tool,
cve_id) — so the same finding with updated description text still
matches as "unchanged".
"""

import logging

logger = logging.getLogger('scanner')

# Fields used to build a finding fingerprint. Two findings with the same
# fingerprint are considered the same finding.
FINGERPRINT_FIELDS = ('title', 'severity', 'tool', 'cve_id')


def _finding_fingerprint(finding: dict) -> str:
    """
    Build a stable fingerprint string for a finding so we can match
    the same finding across two reports even if the description or
    evidence text changes slightly.
    """
    parts = []
    for field in FINGERPRINT_FIELDS:
        val = finding.get(field, '') or ''
        parts.append(str(val).strip().lower())
    return '|'.join(parts)


def compare_reports(old_findings: list, new_findings: list) -> dict:
    """
    Compare two lists of findings (from ScanReport.findings_json).

    Returns:
        {
            'new_findings':       [...],
            'resolved_findings':  [...],
            'unchanged_findings': [...],
            'severity_delta':     { 'critical': -2, 'high': +1, ... },
            'new_critical_count': int,
            'new_high_count':     int,
        }
    """
    old_map = {}
    for f in old_findings or []:
        fp = _finding_fingerprint(f)
        old_map[fp] = f

    new_map = {}
    for f in new_findings or []:
        fp = _finding_fingerprint(f)
        new_map[fp] = f

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    new_fingerprints       = new_keys - old_keys
    resolved_fingerprints  = old_keys - new_keys
    unchanged_fingerprints = old_keys & new_keys

    new_findings_list       = [new_map[k]  for k in new_fingerprints]
    resolved_findings_list  = [old_map[k]  for k in resolved_fingerprints]
    unchanged_findings_list = [new_map[k] for k in unchanged_fingerprints]

    # Severity delta: how many of each severity were added/removed
    severities = ('critical', 'high', 'medium', 'low', 'info')
    severity_delta = {}
    for sev in severities:
        old_count = sum(1 for f in old_findings or [] if f.get('severity', '').lower() == sev)
        new_count = sum(1 for f in new_findings or [] if f.get('severity', '').lower() == sev)
        severity_delta[sev] = new_count - old_count

    # Count new critical/high findings (for alerting)
    new_critical_count = sum(1 for f in new_findings_list if f.get('severity', '').lower() == 'critical')
    new_high_count     = sum(1 for f in new_findings_list if f.get('severity', '').lower() == 'high')

    logger.info(
        "Report diff: %d new, %d resolved, %d unchanged, %d new critical, %d new high",
        len(new_findings_list), len(resolved_findings_list),
        len(unchanged_findings_list), new_critical_count, new_high_count,
    )

    return {
        'new_findings':        new_findings_list,
        'resolved_findings':   resolved_findings_list,
        'unchanged_findings':  unchanged_findings_list,
        'severity_delta':      severity_delta,
        'new_critical_count':  new_critical_count,
        'new_high_count':      new_high_count,
    }