import os
import sys
import requests
import yaml
import threading
import argparse

from typing import List, Dict
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.logging_utils import setup_logger
from utils.validation_config import SCHEMA_PLAN


# Initialize logger
logger = setup_logger("vault-bootstrap")

# Load Vault token from env
VAULT_TOKEN = os.getenv("VAULT_TOKEN")


def flat_uuid(uuid: str) -> str:
    """Removes hyphens and converts UUID to lowercase."""
    return uuid.replace("-", "").lower()


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
        error_detail = e.response.text if e.response else str(e)
        logger.error(f"Vault API request failed at {url}: {error_detail}")
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


import json

from jinja2 import Environment, FileSystemLoader

def create_aws_role(flat_uuid: str, role_arns: List[str], base_url: str, vault_cfg: Dict):
    external_id = "vault-gpx"
    session_tags = [f"AppUUID={flat_uuid}"]
    iam_policy_dir = os.path.join(os.path.dirname(__file__), "config", "aws", "IAM", "policies")
    aws_cfg = vault_cfg.get("aws", {})
    accounts = aws_cfg.get("accounts", [])

    jinja_env = Environment(loader=FileSystemLoader(iam_policy_dir))
    combined_policy = {"Version": "2012-10-17", "Statement": []}

    bucket_groups = {}
    for account in accounts:
        services = account.get("services", {})
        if "s3" in services:
            for bucket in services["s3"].get("buckets", []):
                access = bucket.get("access", "readonly")
                logger.info(f"[DEBUG] Detected bucket '{bucket['name']}' with access '{access}'")
                bucket_groups.setdefault(access, []).append(bucket["name"])

    logger.info(f"[DEBUG] Consolidated bucket groups: {bucket_groups}")

    for access in sorted(bucket_groups.keys()):
        bucket_names = sorted(set(bucket_groups[access]))
        template_path = os.path.join("s3", f"{access}.j2")
        template_file = os.path.join(iam_policy_dir, template_path)

        if not os.path.exists(template_file):
            logger.warning(f"[SKIP] Template not found: {template_path}")
            continue

        logger.info(f"[FOUND] Template located: {template_path}")

        if not bucket_names:
            logger.warning(f"[SKIP] No buckets found for access level '{access}', skipping rendering.")
            continue

        logger.info(f"[DEBUG] Rendering policy for access '{access}' with buckets: {bucket_names}")
        template = jinja_env.get_template(template_path)
        rendered_policy = template.render(buckets=bucket_names)
        debug_path = f"/tmp/s3-policy-{access}.json"
        with open(debug_path, "w", encoding="utf-8") as f:
            f.write(rendered_policy)
        logger.info(f"[DEBUG] Rendered policy written to {debug_path}")
        policy_data = json.loads(rendered_policy)
        logger.info(f"[DEBUG] Statements added from access '{access}': {json.dumps(policy_data.get('Statement', []), indent=2)}")
        combined_policy["Statement"].extend(policy_data.get("Statement", []))

    for account in accounts:
        acct_id = account.get("account_id")
        if acct_id:
            role_name = f"{flat_uuid}-{acct_id}"
            payload = {
                "credential_type": "assumed_role",
                "role_arns": [f"arn:aws:iam::{acct_id}:role/{load_assume_role_name()}"],
                "external_id": external_id,
                "session_tags": session_tags,
                "policy_document": json.dumps(combined_policy, indent=2)
            }
            logger.info(f"[DEBUG] Creating AWS IAM role '{role_name}' at {base_url}")
            logger.info(f"[DEBUG] Payload: {payload}")
            try:
                vault_api_request("POST", f"aws/roles/{role_name}", payload, base_url)
                logger.info(f"AWS IAM role '{role_name}' created at {base_url}")
            except Exception as e:
                logger.error(f"Failed to create AWS IAM role '{role_name}' at {base_url}: {e}")
                raise
        
        


def build_policy(uuid_flat: str, enable_kv: bool, enable_aws: bool, vault_cfg: Dict) -> str:
    policy = []
    if enable_kv:
        policy.extend([
            f'path "kv/data/{uuid_flat}/*" {{ capabilities = ["read"] }}',
            f'path "kv/metadata/{uuid_flat}/" {{ capabilities = ["list"] }}',
            f'path "kv/metadata/{uuid_flat}/*" {{ capabilities = ["read"] }}'
        ])
    if enable_aws:
        accounts = vault_cfg.get("aws", {}).get("accounts", [])
        for acct in accounts:
            acct_id = acct.get("account_id")
            if acct_id:
                policy.append(f'path "aws/sts/{uuid_flat}-{acct_id}" {{ capabilities = ["read"] }}')

    return "".join(policy)


def bootstrap_single_vault(vault_url: str, metadata: Dict, vault_cfg: Dict) -> bool:
    try:
        uuid = metadata["appid"]
        uuid_flat = flat_uuid(uuid)
        policy_name = f"{uuid_flat}-policy"

        enable_kv = vault_cfg.get("kv", {}).get("enabled", False)
        enable_aws = vault_cfg.get("aws", {}).get("enabled", False)

        policy = build_policy(uuid_flat, enable_kv, enable_aws, vault_cfg)
        create_policy(policy_name, policy, vault_url)
        create_approle(uuid_flat, policy_name, vault_url)

        if enable_aws:
            assume_role_name = load_assume_role_name()
            accounts = vault_cfg.get("aws", {}).get("accounts", [])
            role_arns = [
                f"arn:aws:iam::{acct['account_id']}:role/{assume_role_name}"
                for acct in accounts
            ]
            create_aws_role(uuid_flat, role_arns, vault_url, vault_cfg)

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


def parse_args() -> argparse.Namespace:
    """
    Constructs an argparse parser based on declared schemas in SCHEMA_PLAN.

    Returns:
        argparse.Namespace containing parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Bootstrap Vault configuration.")
    print("Current Working Directory:", os.getcwd())
    
    # Required args
    parser.add_argument(
        "--env-dir",
        required=True,
        help="Path to the environment-specific folder (e.g., coreops/dev)"
    )
    parser.add_argument(
        "--metadata-file",
        required=True,
        help="YAML file under coreops/metadata/ containing app-level metadata"
    )

    # New argument for VaultOps file
    parser.add_argument(
        "--vaultops-file",
        required=True,
        help="Path to the VaultOps configuration file under the environment directory (e.g., coreops/dev/vault/)"
    )

    # Optional config files derived from SCHEMA_PLAN
    for key, config in SCHEMA_PLAN.items():
        parser.add_argument(
            f"--{key}-file",
            default="",
            help=f"{config['label']} YAML file under environment directory (e.g., vaultops.yaml)"
        )

    return parser.parse_args()


#def list_files_recursively(directory):
#    for root, dirs, files in os.walk(directory):
#        logger.info(f"Directory: {root}")
#        for name in files:
#            file_path = os.path.join(root, name)
#            file_info = os.stat(file_path)
#            logger.info(f"File: {file_path}, Size: {file_info.st_size} bytes, Modified: {file_info.st_mtime}")


if __name__ == "__main__":           
    try:
        args = parse_args()
        # Now you can use args.env_dir, args.metadata_file, etc.

        # Example usage of the parsed arguments
        #print("Metadata File Path:", args.metadata_file)
        #print("VaultOps File Path:", args.vaultops_file)
        #print("Current Working Directory:", os.getcwd())
        #list_files_recursively(os.getcwd())
        vaultops_file_path = os.path.join(args.env_dir, "vault", args.vaultops_file)
        print("VaultOps File Path:", vaultops_file_path)
        logger.info(f"Starting Vault bootstrap for metadata: {args.metadata_file} and config: {args.env_dir}")
        success = bootstrap_to_all_vaults(args.metadata_file, args.env_dir)

        if success:
            logger.info("Bootstrap completed successfully across all Vaults.")
            sys.exit(0)
        else:
            logger.error("Bootstrap failed on one or more Vaults.")
            sys.exit(1)

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)