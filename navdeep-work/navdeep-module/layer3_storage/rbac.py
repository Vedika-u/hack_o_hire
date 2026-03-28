from layer3_storage.es_client import get_es_client


def create_roles():
    """Create SOC roles with proper index permissions"""
    client = get_es_client()

    roles = {
        "soc_analyst": {
            "indices": [{
                "names": [
                    "soc-raw-logs", "soc-aggregated-behavior",
                    "soc-user-features", "soc-anomaly-scores",
                    "soc-posture-risk"
                ],
                "privileges": ["read", "view_index_metadata"]
            }]
        },
        "soc_responder": {
            "indices": [{
                "names": [
                    "soc-raw-logs", "soc-aggregated-behavior",
                    "soc-user-features", "soc-anomaly-scores",
                    "soc-posture-risk", "soc-audit-logs"
                ],
                "privileges": ["read", "write", "view_index_metadata"]
            }]
        },
        "soc_admin": {
            "indices": [{
                "names": ["soc-*"],
                "privileges": ["all"]
            }]
        }
    }

    for role_name, role_body in roles.items():
        client.security.put_role(name=role_name, body=role_body)
        print(f"  ✅ Role created: {role_name}")


def create_users():
    """Create SOC users mapped to roles"""
    client = get_es_client()

    users = {
        "analyst1":   {"password": "Analyst@1234",   "roles": ["soc_analyst"]},
        "responder1": {"password": "Responder@1234", "roles": ["soc_responder"]},
        "admin1":     {"password": "Admin@1234",     "roles": ["soc_admin"]}
    }

    for username, info in users.items():
        client.security.put_user(
            username=username,
            body={
                "password":  info["password"],
                "roles":     info["roles"],
                "full_name": username.capitalize(),
                "email":     f"{username}@actaware.local"
            }
        )
        print(f"  ✅ User created: {username} → {info['roles']}")


def setup_rbac():
    """Full RBAC setup"""
    print("\n🔐 Setting up RBAC...")
    create_roles()
    create_users()
    print("✅ RBAC setup complete!\n")


if __name__ == "__main__":
    setup_rbac()