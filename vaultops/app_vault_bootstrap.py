import os
import sys
import requests
import yaml
import threading
from typing import List, Dict

from utils.logging_utils import get_logger

# Initialize logger
logger = get_logger("vault-bootstrap")

# Load Vault token from env
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


def flat_uuid(uuid: str) -> str:
    """Removes hyphens from a UUID."""
    return uuid.replace("-", "")


def read_yaml(path: str) -> Dict:
    """Reads and parses a YAML file."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_global_defaults() -> Dict:
    """Loads global AppRole defaults and vault settings from vaultops/config/defaults.yaml."""
    path = os.path.join(os.path.dirname(__file__), "config", "defaults.yaml")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_vault_endpoints() -> Dict:
    """Loads Vault site endpoints from vaultops/config/defaults.yaml."""
    return load_global_defaults().get("vault_endpoints", {})


def load_assume_role_name() -> str:
    """Returns the global AWS IAM role name used for Vault STS."""
    return load_global_defaults().get("aws_assume_role_name", "VaultAssumeTrustPolicyRole")


def vault_api_request(method: str, path: str, json: Dict = None, base_url: str = None):
    """Generic helper to make Vault API calls."""
    url = f"{base_url}/v1/{path}"
    headers = {"X-Vault-Token": VAULT_TOKEN}
    try:
        response = requests.request(method, url, headers=headers, json=json)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Vault API request failed at {url}: {e}")
        raise


def create_policy(name: str, policy_hcl: str, base_url: str):
    try:
        vault_api_request("PUT", f"sys/policies/acl/{name}", {"policy": policy_hcl}, base_url)
        logger.info(f"Policy '{name}' created at {base_url}")
    except Exception as e:
        logger.error(f"Failed to create policy '{name}' at {base_url}: {e}")
        raise


def create_approle(role_name: str, policy_name: str, base_url: str):
    defaults = load_global_defaults().get("approle_defaults", {})
    payload = {"token_policies": policy_name, **defaults}
    try:
        vault_api_request("POST", f"auth/approle/role/{role_name}", payload, base_url)
        logger.info(f"AppRole '{role_name}' created at {base_url}")
    except Exception as e:
        logger.error(f"Failed to create AppRole '{role_name}' at {base_url}: {e}")
        raise


def create_aws_role(flat_uuid: str, role_arns: List[str], base_url: str):
    payload = {"credential_type": "assumed_role", "role_arns": role_arns}
    try:
        vault_api_request("POST", f"aws/sts/{flat_uuid}", payload, base_url)
        logger.info(f"AWS STS role '{flat_uuid}' created at {base_url}")
    except Exception as e:
        logger.error(f"Failed to create AWS STS role '{flat_uuid}' at {base_url}: {e}")
        raise


def build_policy(uuid_flat: str, enable_kv: bool, enable_aws: bool) -> str:
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


def bootstrap_single_vault(vault_url: str, metadata: Dict, vault_cfg: Dict) -> bool:
    try:
        uuid = metadata["app_id"]
        uuid_flat = flat_uuid(uuid)
        policy_name = f"{uuid_flat}-policy"

        enable_kv = vault_cfg.get("kv", {}).get("enabled", False)
        enable_aws = vault_cfg.get("aws", {}).get("enabled", False)

        policy = build_policy(uuid_flat, enable_kv, enable_aws)
        create_policy(policy_name, policy, vault_url)
        create_approle(uuid_flat, policy_name, vault_url)

        if enable_aws:
            assume_role_name = load_assume_role_name()
            accounts = vault_cfg.get("aws", {}).get("accounts", [])
            role_arns = [
                f"arn:aws:iam::{acct['account_id']}:role/{assume_role_name}"
                for acct in accounts
            ]
            create_aws_role(uuid_flat, role_arns, vault_url)

        logger.info(f"Vault bootstrap completed successfully for {vault_url}")
        return True
    except Exception as e:
        logger.error(f"Bootstrap process failed for {vault_url}: {e}")
        print(f"::error::Vault bootstrap failed for {vault_url}")
        return False


def bootstrap_to_all_vaults(metadata_path: str, vault_path: str):
    metadata = read_yaml(metadata_path)
    vault_cfg = read_yaml(vault_path).get("vault", {})
    vault_endpoints = load_vault_endpoints()

    results = {}
    threads = []

    def worker(site: str, url: str):
        result = bootstrap_single_vault(url, metadata, vault_cfg)
        results[site] = result

    for site, url in vault_endpoints.items():
        thread = threading.Thread(target=worker, args=(site, url))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return all(results.values())


# Example usage:
# success = bootstrap_to_all_vaults("tars/metadata.yaml", "tars/dev/vault.yaml")
# sys.exit(0 if success else 1)
