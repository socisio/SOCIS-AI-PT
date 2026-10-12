"""Rules that stop an admin from locking everyone out, plus input validation for admin-created users."""
from __future__ import annotations

import re
from typing import Iterable, Optional

# Roles an admin may assign. ("api_user" exists only for API keys and is not a login role.)
ASSIGNABLE_ROLES = ("admin", "analyst", "viewer")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,49}$")


def is_effective_admin(role_names: Iterable) -> bool:
    """True if the user can actually use admin features.

    Permissions are granted by the ROLE in the user's token (user.roles[0].name). The `is_superuser` flag grants
    nothing on the backend, so a superuser whose role is "viewer" is NOT an admin, and must not be counted as one
    by the self-lockout / last-admin rules.
    """
    return "admin" in {str(r) for r in role_names}


def _n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def describe_delete_blockers(*, projects: int = 0, scans: int = 0, reports: int = 0, schedules: int = 0) -> Optional[str]:
    """Explain why a user cannot be deleted, or None if nothing blocks it.

    Projects, scans, reports and scan schedules must have an owner (NOT NULL, no cascade), so deleting their
    owner would orphan real work. The admin should deactivate the account instead (this signs the user out
    and keeps the history).
    """
    parts = []
    if projects:
        parts.append(f"owns {_n(projects, 'project', 'projects')}")
    if scans:
        parts.append(f"started {_n(scans, 'scan', 'scans')}")
    if reports:
        parts.append(f"generated {_n(reports, 'report', 'reports')}")
    if schedules:
        parts.append(f"created {_n(schedules, 'scan schedule', 'scan schedules')}")
    if not parts:
        return None
    return ("This user can't be deleted because they " + ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1]
            + ". Deleting would orphan that work. Deactivate the account instead: it signs them out and keeps the history.")


def validate_username(username: str) -> Optional[str]:
    """Return an error message, or None if the username is acceptable."""
    if not isinstance(username, str) or not _USERNAME_RE.match(username):
        return "Username must be 3-50 characters: letters, digits, '.', '_' or '-', starting with a letter or digit"
    return None


def check_admin_safety(*, actor_id, target_id, target_is_admin_now: bool, target_will_be_admin: bool,
                       target_will_be_active: bool, active_admin_ids: Iterable) -> Optional[str]:
    """Return an error message if this change would remove admin access in a harmful way, else None.

    - An admin may not remove their own admin access or deactivate/delete themselves.
    - The last active administrator may not be demoted, deactivated or deleted.
    """
    if not target_is_admin_now:
        return None
    losing_admin = (not target_will_be_admin) or (not target_will_be_active)
    if not losing_admin:
        return None
    if str(actor_id) == str(target_id):
        return "You can't remove your own admin access or deactivate your own account. Ask another admin to do it."
    remaining = {str(a) for a in active_admin_ids} - {str(target_id)}
    if not remaining:
        return "This is the last active administrator. Create or promote another admin first."
    return None
