import os
import sys
import requests
import yaml
import threading
import argparse

from typing import List, Dict
from pathlib import Path

# Add the parent directory to the system path for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import utility modules for logging and schema validation
from utils.logging_utils import setup_logger
from utils.schema_validator import validate_yaml

from utils.validation_config import SCHEMA_PLAN

# Initialize the logger for this script
logger = setup_logger("vault-bootstrap")

# Load the Vault token from environment variables
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

def flat_uuid(uuid: str) -> str:
    """Removes hyphens and converts UUID to lowercase."""
    return uuid.replace("-", "").lower()

def read_yaml(path: str) -> Dict:
    """Reads and parses a YAML file."""
    with open(path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

def bootstrap_to_all_vaults(metadata_path: str, app_vault_config_path: str):
    """
    Bootstraps configurations to all Vaults using metadata and app vault configuration.

    Args:
        metadata_path (str): Path to the metadata YAML file.
        app_vault_config_path (str): Path to the app vault configuration YAML file.

    Returns:
        bool: True if bootstrapping is successful across all Vaults, False otherwise.
    """
    metadata = read_yaml(metadata_path)
    vault_cfg = read_yaml(app_vault_config_path).get("vault", {})
    vault_endpoints = load_vault_endpoints()

    results = {}
    for endpoint in vault_endpoints:
        try:
            # Perform bootstrapping for each Vault endpoint
            success = bootstrap_vault(endpoint, metadata, vault_cfg, token)
            results[endpoint] = success
        except Exception as e:
            logger.error(f"Error bootstrapping {endpoint}: {e}")
            results[endpoint] = False

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
    parser.add_argument(
        "--vaultops-file",
        required=True,
        help="Path to the VaultOps configuration file under the environment directory (e.g., coreops/dev/vault/)"
    )

    return parser.parse_args()

if __name__ == "__main__":           
    try:
        args = parse_args()
        # Validate metadata and vaultops schema before proceeding
        metadata_path = args.metadata_file  # e.g., coreops/metadata/tars.yaml
        vaultops_path = os.path.join(args.env_dir, "vault", args.vaultops_file)
        validate_yaml(metadata_path, "metadata")
        validate_yaml(vaultops_path, "vaultops")
        logger.info(f"Starting Vault bootstrap for metadata: {metadata_path} and config: {vaultops_path}")
        success = bootstrap_to_all_vaults(args.metadata_file, vaultops_path)

        if success:
            logger.info("Bootstrap completed successfully across all Vaults.")
        else:
            logger.error("Bootstrap failed on one or more Vaults.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)