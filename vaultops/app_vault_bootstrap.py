import os
import sys
import requests
import yaml
from typing import List, Dict

from utils.logging_utils import get_logger

# Initialize logger
logger = get_logger("vault-bootstrap")

# Load Vault environment
VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
HEADERS = {"X-Vault-Token": VAULT_TOKEN}


def flat_uuid(uuid: str) -> str:
    """Removes hyphens from a UUID."""
    return uuid.replace("-", "")


def read_yaml(path: str) -> Dict:
    """Reads and parses a YAML file."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def vault_api_request(method: str, path: str, json: Dict = None):
    """Generic helper to make Vault API calls."""
    url = f"{VAULT_ADDR}/v1/{path}"
    try:
        response = requests.request(method, url, headers=HEADERS, json=json)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Vault API request failed at {path}: {e}")
        raise


def create_policy(name: str, policy_hcl: str):
    """Creates a Vault ACL policy."""
    try:
        vault_api_request("PUT", f"sys/policies/acl/{name}", {"policy": policy_hcl})
        logger.info(f"Policy '{name}' successfully created")
    except Exception as e:
        logger.error(f"Failed to create policy '{name}': {e}")
        raise


def create_approle(role_name: str, policy_name: str, config: Dict):
    """Creates an AppRole with configuration loaded from vault.yaml."""
    payload = {
        "token_policies": policy_name,
        "bind_secret_id": config.get("bind_secret_id", True),
        "secret_id_ttl": config.get("secret_id_ttl", "24h"),
        "secret_id_num_uses": config.get("secret_id_num_uses", 10),
        "token_ttl": config.get("token_ttl", "1h"),
        "token_max_ttl": config.get("token_max_ttl", "4h"),
    }
    try:
        vault_api_request("POST", f"auth/approle/role/{role_name}", payload)
        logger.info(f"AppRole '{role_name}' successfully created")
    except Exception as e:
        logger.error(f"Failed to create AppRole '{role_name}': {e}")
        raise


def create_aws_role(flat_uuid: str, role_arns: List[str]):
    """Creates an AWS STS role with provided ARNs."""
    payload = {
        "credential_type": "assumed_role",
        "role_arns": role_arns
    }
    try:
        vault_api_request("POST", f"aws/sts/{flat_uuid}", payload)
        logger.info(f"AWS STS role '{flat_uuid}' successfully created")
    except Exception as e:
        logger.error(f"Failed to create AWS STS role '{flat_uuid}': {e}")
        raise


def build_policy(uuid_flat: str, enable_kv: bool, enable_aws: bool) -> str:
    """Builds the Vault policy HCL based on enabled backends."""
    policy = []

    if enable_kv:
        policy.extend([
            f'path "kv/data/{uuid_flat}/*" {{ capabilities = ["read"] }}',
            f'path "kv/metadata/{uuid_flat}/" {{ capabilities = ["list"] }}',
            f'path "kv/metadata/{uuid_flat}/*" {{ capabilities = ["read"] }}'
        ])

    if enable_aws:
        policy.append(f'path "aws/sts/{uuid_flat}" {{ capabilities = ["read"] }}')

    return "\n".join(policy)


def bootstrap(metadata_path: str, vault_path: str):
    """
    Bootstrap process to:
    - Read metadata and vault configuration
    - Construct policy
    - Create Vault policy, AppRole, and AWS role
    Returns True on success, False on failure for CI integration.
    """
    try:
        metadata = read_yaml(metadata_path)
        vault_cfg = read_yaml(vault_path).get("vault", {})

        uuid = metadata["app_id"]
        uuid_flat = flat_uuid(uuid)
        policy_name = f"{uuid_flat}-policy"

        enable_kv = vault_cfg.get("kv", {}).get("enabled", False)
        enable_aws = vault_cfg.get("aws", {}).get("enabled", False)

        policy = build_policy(uuid_flat, enable_kv, enable_aws)
        create_policy(policy_name, policy)
        create_approle(uuid_flat, policy_name, vault_cfg.get("approle", {}))

        if enable_aws:
            accounts = vault_cfg.get("aws", {}).get("accounts", [])
            role_arns = [
                f"arn:aws:iam::{acct['account_id']}:role/vault-assume-role"
                for acct in accounts
            ]
            create_aws_role(uuid_flat, role_arns)

        logger.info("Vault bootstrap completed successfully.")
        return True

    except Exception as e:
        logger.error(f"Bootstrap process failed: {e}")
        print("::error::Vault bootstrap failed")  # GitHub Actions-compatible error output
        return False


# Example usage:
# success = bootstrap("tars/metadata.yaml", "tars/dev/vault.yaml")
# sys.exit(0 if success else 1)
