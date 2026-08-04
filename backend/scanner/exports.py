"""
SARIF (Static Analysis Results Interchange Format) export.
Converts VulnSploit findings to SARIF 2.1.0 format for ingestion by
GitHub Security, Azure DevOps, Splunk, and other security platforms.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json

SARIF_VERSION = '2.1.0'
SARIF_SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json'

SEVERITY_MAP = {
    'critical': 'error',
    'high':     'error',
    'medium':   'warning',
    'low':      'note',
    'info':     'none',
}


def findings_to_sarif(findings: list, target: str = '') -> dict:
    """
    Convert a list of finding dicts to SARIF 2.1.0 format.

    Returns a SARIF log object ready to be serialized as JSON.
    """
    results = []
    rules = {}
    rule_indices = {}

    for i, f in enumerate(findings):
        # Build a rule entry for this finding type
        rule_id = f.get('tool', 'generic') + ':' + (f.get('cve_id') or f.get('title', f'finding-{i}'))[:80]
        if rule_id not in rule_indices:
            rule_indices[rule_id] = len(rules)
            rules[rule_id] = {
                'id': rule_id,
                'name': f.get('title', 'Security Finding')[:120],
                'shortDescription': {
                    'text': f.get('title', 'Security Finding')[:200],
                },
                'fullDescription': {
                    'text': f.get('description', '')[:1000] or 'No description available.',
                },
                'helpUri': f.get('nvd_url') or f.get('references', [None])[0] if isinstance(f.get('references'), list) else None,
                'defaultConfiguration': {
                    'level': SEVERITY_MAP.get(f.get('severity', 'info').lower(), 'note'),
                },
            }

        # Locations
        locations = [{
            'physicalLocation': {
                'artifactLocation': {
                    'uri': target or f.get('target', 'unknown'),
                },
            },
        }]

        # Code flows for CVEs (link to NVD)
        code_flows = None
        if f.get('cve_id'):
            code_flows = [{
                'threadFlows': [{
                    'locations': [{
                        'location': {
                            'physicalLocation': {
                                'artifactLocation': {'uri': f.get('nvd_url', '')},
                            },
                        },
                    }],
                }],
            }]

        result = {
            'ruleId': rule_id,
            'ruleIndex': rule_indices[rule_id],
            'level': SEVERITY_MAP.get(f.get('severity', 'info').lower(), 'note'),
            'message': {
                'text': f.get('description', f.get('title', 'Security Finding'))[:5000],
            },
            'locations': locations,
            'partialFingerprints': {
                'vulnsploit/primary': f.get('title', '')[:200] + '|' + f.get('tool', ''),
            },
        }

        # Add CWE if available
        cwe_ids = f.get('cwe_ids', [])
        if cwe_ids:
            result['taxa'] = [{
                'tool': {'name': 'CWE'},
                'id': cwe_ids[0],
            }]

        # Add OWASP tag if available
        if f.get('owasp'):
            result['properties'] = {
                'owasp': f.get('owasp'),
                'owasp_name': f.get('owasp_name', ''),
            }

        # Add exploit-availability flag
        if f.get('public_exploit'):
            if 'properties' not in result:
                result['properties'] = {}
            result['properties']['public_exploit'] = True

        if f.get('known_exploited'):
            if 'properties' not in result:
                result['properties'] = {}
            result['properties']['known_exploited'] = True

        if code_flows:
            result['codeFlows'] = code_flows

        results.append(result)

    sarif_log = {
        '$schema': SARIF_SCHEMA,
        'version': SARIF_VERSION,
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'VulnSploit',
                    'version': '1.0',
                    'informationUri': 'https://github.com/Strawhat404/Vulnsploit',
                    'rules': list(rules.values()),
                },
            },
            'results': results,
        }],
    }

    return sarif_log


def findings_to_json(findings: list, report_data: dict) -> dict:
    """
    Export findings + report metadata as a plain JSON dict.
    Simpler than SARIF, for VulnSploit's own API consumers.
    """
    return {
        'report': {
            'id': report_data.get('id'),
            'target': report_data.get('target'),
            'risk_level': report_data.get('risk_level'),
            'posture_score': report_data.get('posture_score'),
            'severity_counts': report_data.get('severity_counts'),
            'total_findings': report_data.get('total_findings'),
            'dedup_stats': report_data.get('dedup_stats'),
            'compliance_summary': report_data.get('compliance_summary'),
            'generated_at': str(report_data.get('generated_at', '')),
        },
        'findings': findings,
    }