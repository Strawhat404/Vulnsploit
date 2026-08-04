"""
VulnSploit project-level middleware lives here.
"""

import logging

logger = logging.getLogger('scanner')

# Methods that mutate state and should be recorded in the audit log.
_AUDITED_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}

# Only audit requests directed at the API surface.
_AUDITED_PREFIX = '/api/'


class AuditLogMiddleware:
    """
    Records write-method API requests to the AuditLog table. Tries to attach
    the acting user and their primary organization (if any) for review by
    enterprise customers. Failures are swallowed so audit logging never
    breaks the request cycle.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        self._record(request, response)
        return response

    def _record(self, request, response):
        if request.method not in _AUDITED_METHODS:
            return
        if not request.path.startswith(_AUDITED_PREFIX):
            return

        try:
            from scanner.models import AuditLog, Organization

            user = request.user if getattr(request, 'user', None) and request.user.is_authenticated else None

            # Best-effort: derive the user's primary organization (most recent
            # membership) for grouping the audit record.
            org = None
            if user is not None:
                membership = (
                    user.memberships.select_related('organization')
                    .order_by('-joined_at').first()
                )
                org = membership.organization if membership else None

            ip = (
                request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                or request.META.get('REMOTE_ADDR')
            )
            if ip:
                try:
                    import ipaddress
                    ipaddress.ip_address(ip)
                except ValueError:
                    ip = None

            user_agent = (request.META.get('HTTP_USER_AGENT') or '')[:500]

            view_name = ''
            if getattr(request, 'resolver_match', None) and request.resolver_match:
                view_name = request.resolver_match.view_name or ''

            AuditLog.objects.create(
                user=user,
                organization=org,
                action=f"{request.method} {request.path}",
                resource_type=view_name,
                ip_address=ip or None,
                user_agent=user_agent,
                metadata={'status_code': response.status_code},
            )
        except Exception as exc:  # pragma: no cover - never fail the request
            logger.warning("AuditLogMiddleware failed: %s", str(exc))