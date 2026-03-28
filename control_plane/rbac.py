# control_plane/rbac.py
"""
Role-Based Access Control for ACT AWARE.
Uses plain Python classes to avoid pydantic version conflicts.
"""

from enum import Enum
from typing import Set, Optional


# ────────────────────────────────────────
# ROLES
# ────────────────────────────────────────

class Role(str, Enum):
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    SOC_MANAGER = "soc_manager"
    ADMIN = "admin"


# ────────────────────────────────────────
# PERMISSIONS
# ────────────────────────────────────────

class Permission(str, Enum):
    VIEW_INCIDENTS = "view_incidents"
    VIEW_PLAYBOOKS = "view_playbooks"
    VIEW_METRICS = "view_metrics"
    APPROVE_STANDARD_ACTIONS = "approve_standard_actions"
    APPROVE_CRITICAL_ACTIONS = "approve_critical_actions"
    REJECT_PLAYBOOK = "reject_playbook"
    EXECUTE_ACTIONS = "execute_actions"
    TRIGGER_LLM = "trigger_llm"
    MANAGE_USERS = "manage_users"
    MANAGE_POLICIES = "manage_policies"
    VIEW_AUDIT_LOG = "view_audit_log"
    TRIGGER_RETRAINING = "trigger_retraining"


# ────────────────────────────────────────
# ROLE → PERMISSION MAPPING
# ────────────────────────────────────────

ROLE_PERMISSIONS = {
    Role.ANALYST: {
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_PLAYBOOKS,
        Permission.VIEW_METRICS,
        Permission.APPROVE_STANDARD_ACTIONS,
        Permission.REJECT_PLAYBOOK,
    },
    Role.SENIOR_ANALYST: {
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_PLAYBOOKS,
        Permission.VIEW_METRICS,
        Permission.APPROVE_STANDARD_ACTIONS,
        Permission.APPROVE_CRITICAL_ACTIONS,
        Permission.REJECT_PLAYBOOK,
        Permission.TRIGGER_LLM,
        Permission.VIEW_AUDIT_LOG,
    },
    Role.SOC_MANAGER: {
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_PLAYBOOKS,
        Permission.VIEW_METRICS,
        Permission.APPROVE_STANDARD_ACTIONS,
        Permission.APPROVE_CRITICAL_ACTIONS,
        Permission.REJECT_PLAYBOOK,
        Permission.EXECUTE_ACTIONS,
        Permission.TRIGGER_LLM,
        Permission.VIEW_AUDIT_LOG,
        Permission.MANAGE_POLICIES,
        Permission.TRIGGER_RETRAINING,
    },
    Role.ADMIN: set(Permission),
}


# ────────────────────────────────────────
# USER CLASS (plain Python, no pydantic)
# ────────────────────────────────────────

class User:
    """Represents an authenticated user with role-based permissions."""

    def __init__(self, username: str, role: Role, is_active: bool = True):
        self.username = username
        self.role = role
        self.is_active = is_active

    def has_permission(self, permission: Permission) -> bool:
        """Check if this user has a specific permission."""
        if not self.is_active:
            return False
        return permission in ROLE_PERMISSIONS.get(self.role, set())

    def get_permissions(self) -> Set[Permission]:
        """Get all permissions for this user's role."""
        return ROLE_PERMISSIONS.get(self.role, set())


# ────────────────────────────────────────
# USER DATABASE (Mock)
# Password for all users: "password123"
# Using hashlib instead of bcrypt (Python 3.14 compatible)
# ────────────────────────────────────────

import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

PASSWORD_HASH = hash_password("password123")

USERS_DB = {
    "analyst1": {
        "username": "analyst1",
        "password_hash": PASSWORD_HASH,
        "role": Role.ANALYST,
        "is_active": True,
    },
    "senior1": {
        "username": "senior1",
        "password_hash": PASSWORD_HASH,
        "role": Role.SENIOR_ANALYST,
        "is_active": True,
    },
    "manager1": {
        "username": "manager1",
        "password_hash": PASSWORD_HASH,
        "role": Role.SOC_MANAGER,
        "is_active": True,
    },
    "admin1": {
        "username": "admin1",
        "password_hash": PASSWORD_HASH,
        "role": Role.ADMIN,
        "is_active": True,
    },
}