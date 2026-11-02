"""
Organization role enforcement.

Roles, lowest to highest:
  viewer   read everything in the organization
  analyst  + launch scans/recon/reports, cancel jobs, triage findings
  admin    + manage targets (and verify them), schedules, webhooks,
             analysts and viewers; read the organization audit log
  owner    + edit/delete the organization, manage admins and owners

Objects with no organization are private to their user and are not subject
to roles (the queryset already limits them to the owner).
"""

from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import SAFE_METHODS

from .models import OrganizationMember

ROLE_RANK = {'viewer': 0, 'analyst': 1, 'admin': 2, 'owner': 3}


def role_in_org(user, org):
    """The user's role in ``org`` (instance or id), or None if not a member."""
    org_id = getattr(org, 'id', org)
    if org_id is None or not getattr(user, 'is_authenticated', False):
        return None
    return (
        OrganizationMember.objects.filter(user=user, organization_id=org_id)
        .values_list('role', flat=True).first()
    )


def has_role(user, org, min_role: str) -> bool:
    role = role_in_org(user, org)
    return role is not None and ROLE_RANK[role] >= ROLE_RANK[min_role]


def require_role(user, org, min_role: str) -> None:
    """Raise 403 unless ``user`` holds at least ``min_role`` in ``org``."""
    if getattr(org, 'id', org) is None:
        return  # private object
    if not has_role(user, org, min_role):
        raise PermissionDenied(f'This action requires the {min_role} role in this organization.')


class OrgRoleMixin:
    """
    For generic views / viewsets whose objects carry an ``organization``.
    Reads need ``read_role``; any other method needs ``write_role``. Creation
    is checked separately through ``resolve_org(request, min_role=...)``.
    """
    read_role = 'viewer'
    write_role = 'analyst'

    def check_object_permissions(self, request, obj):
        super().check_object_permissions(request, obj)
        need = self.read_role if request.method in SAFE_METHODS else self.write_role
        require_role(request.user, getattr(obj, 'organization_id', None), need)
