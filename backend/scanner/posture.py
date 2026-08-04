"""
Security posture score calculation.
Produces a 0-100 score (higher = better security posture) from
severity counts. The score penalizes critical/high findings heavily
and gives partial credit for having no findings at all.
"""


def calculate_posture_score(severity_counts: dict, total_findings: int) -> int:
    """
    Calculate a 0-100 security posture score.

    Scoring model:
      - Start at 100 (perfect)
      - Critical findings: -15 each (max -60)
      - High findings:     -8 each  (max -40)
      - Medium findings:   -3 each  (max -20)
      - Low findings:      -1 each  (max -10)
      - Info findings:     0        (no penalty)

    The result is clamped to [0, 100]. An asset with zero findings
    scores 100. An asset with 4+ critical findings scores around 0.

    This is intentionally simple — it gives a quick at-a-glance
    metric for dashboards. A more sophisticated model could weight
    by EPSS, asset criticality, and exploit availability.
    """
    if total_findings == 0:
        return 100

    crit  = severity_counts.get('critical', 0)
    high  = severity_counts.get('high', 0)
    med   = severity_counts.get('medium', 0)
    low   = severity_counts.get('low', 0)

    penalty  = min(crit * 15, 60)
    penalty += min(high *  8, 40)
    penalty += min(med  *  3, 20)
    penalty += min(low  *  1, 10)

    return max(0, 100 - penalty)


def posture_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade for dashboard display."""
    if score >= 90: return 'A'
    if score >= 80: return 'B'
    if score >= 70: return 'C'
    if score >= 60: return 'D'
    return 'F'


def posture_label(score: int) -> str:
    """Map a 0-100 score to a qualitative label."""
    if score >= 90: return 'Excellent'
    if score >= 75: return 'Good'
    if score >= 60: return 'Fair'
    if score >= 40: return 'Poor'
    return 'Critical'