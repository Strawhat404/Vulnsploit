"""
Finding deduplication / correlation engine.
Merges overlapping findings from multiple scan tools before they reach
the report or API. Two findings are considered duplicates if they share
the same normalized fingerprint. The merged finding retains the highest
severity and combines evidence from all sources.
"""

import logging

logger = logging.getLogger('scanner')

# Severity ranking (lower number = more severe)
SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def _dedup_fingerprint(finding: dict) -> str:
    """
    Build a fingerprint for deduplication. Two findings with the same
    fingerprint are merged into one.

    Strategy:
    - CVE findings: fingerprint on cve_id (unique per vulnerability)
    - Port findings: fingerprint on (port, protocol) — nmap/whatweb/nikto
      may all report the same open port
    - Header findings: fingerprint on header name — only one finding per
      missing/misconfigured security header
    - SSL cert findings: fingerprint on cert status
    - Other: fingerprint on normalized title + severity
    """
    import re
    tool = finding.get('tool', '')
    cve_id = finding.get('cve_id', '')
    title = finding.get('title', '')
    evidence = finding.get('evidence', '')

    # CVE findings — unique by CVE ID
    if cve_id:
        return f"cve:{cve_id}"

    # Port findings — unique by port/protocol (search title + evidence)
    if tool in ('nmap', 'whatweb') or 'Port' in title or 'Port' in evidence:
        port_match = re.search(r'Port (\d+)/(tcp|udp)', title + ' ' + evidence)
        if port_match:
            return f"port:{port_match.group(1)}:{port_match.group(2)}"

    # Header findings — unique by header name (search title + evidence + description)
    if tool == 'headers' or 'header' in title.lower() or 'Missing' in title:
        header_match = re.search(
            r'(Strict-Transport-Security|Content-Security-Policy|'
            r'X-Frame-Options|X-Content-Type-Options|Referrer-Policy|'
            r'Permissions-Policy|X-XSS-Protection|Server|'
            r'X-Powered-By|X-AspNet-Version|SSL Certificate)',
            title + ' ' + evidence + ' ' + finding.get('description', ''),
            re.IGNORECASE,
        )
        if header_match:
            return f"header:{header_match.group(1).lower()}"

    # Technology findings — whatweb/nikto may report same tech
    if tool == 'whatweb' and 'Technology' in title:
        return f"tech:{title.lower().strip()}"

    # Nuclei findings — unique by template-id if present
    if tool == 'nuclei':
        tid = re.search(r'template[:\-]id[:\s]+([^\s|]+)', evidence, re.IGNORECASE)
        if tid:
            return f"nuclei:{tid.group(1)}"
        return f"nuclei:{title.lower().strip()}"

    # SSL cert findings
    if 'SSL Certificate' in title or 'certificate' in title.lower():
        return f"ssl:{title.lower().strip()}"

    # Generic: title + severity (normalized)
    return f"generic:{title.lower().strip()}:{finding.get('severity', 'info').lower()}"


def deduplicate_findings(findings: list) -> tuple:
    """
    Deduplicate a list of finding dicts.

    Returns:
        (deduplicated_findings, dedup_stats)
        dedup_stats = {
            'original_count': int,
            'deduplicated_count': int,
            'removed_count': int,
            'merged_groups': int,
        }
    """
    if not findings:
        return [], {
            'original_count': 0,
            'deduplicated_count': 0,
            'removed_count': 0,
            'merged_groups': 0,
        }

    # Group findings by fingerprint
    groups = {}  # fingerprint → [findings]
    group_order = []  # preserve order of first appearance

    for f in findings:
        fp = _dedup_fingerprint(f)
        if fp not in groups:
            groups[fp] = []
            group_order.append(fp)
        groups[fp].append(f)

    merged_count = 0
    result = []

    for fp in group_order:
        group = groups[fp]

        if len(group) == 1:
            result.append(group[0])
            continue

        # Multiple findings share this fingerprint — merge them
        merged_count += 1

        # Pick the highest severity as the primary
        primary = min(group, key=lambda x: SEVERITY_RANK.get(
            x.get('severity', 'info').lower(), 4
        ))

        merged = dict(primary)  # copy the primary finding

        # Combine evidence from all sources
        all_tools = list(dict.fromkeys(f.get('tool', '') for f in group if f.get('tool')))
        all_evidence = list(dict.fromkeys(
            f.get('evidence', '') for f in group if f.get('evidence')
        ))

        if len(all_tools) > 1:
            merged['tools'] = all_tools
            merged['tool'] = all_tools[0]  # keep primary tool for severity sorting

        if len(all_evidence) > 1:
            merged['evidence'] = ' | '.join(all_evidence[:3])
            merged['correlated_sources'] = len(group)

        # Merge any fields from non-primary findings that primary lacks
        for f in group:
            for k, v in f.items():
                if k not in merged or not merged[k]:
                    merged[k] = v

        result.append(merged)

    removed = len(findings) - len(result)

    logger.info(
        "Deduplication: %d findings → %d (removed %d duplicates, %d merge groups)",
        len(findings), len(result), removed, merged_count,
    )

    return result, {
        'original_count': len(findings),
        'deduplicated_count': len(result),
        'removed_count': removed,
        'merged_groups': merged_count,
    }