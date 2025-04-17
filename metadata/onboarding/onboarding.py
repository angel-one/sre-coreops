import argparse
import json
import sys
import yaml
import jsonschema

from pathlib import Path
from typing import Any

# Add the root-level `coreops/` directory to the Python path so we can import shared modules
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Import shared logger and the validation schema plan
from utils.logging_utils import setup_logger
from utils.validation_config import SCHEMA_PLAN

# Initialize a logger for this script with a clear namespace
logger = setup_logger("coreops.onboarding")

# Define important file paths relative to this script's location
SCRIPT_DIR = Path(__file__).resolve().parent
SCHEMA_DIR = SCRIPT_DIR.parents[1] / "schemas"  # Points to /schemas/
METADATA_DIR = SCRIPT_DIR.parents[2] / "coreops" / "metadata"  # Points to /coreops/metadata/


# Custom exception to represent schema validation failures separately
class ValidationError(Exception):
    """Raised when schema validation fails and should stop the pipeline."""


# Load and return YAML data from a file path
def load_yaml(file_path: Path) -> dict[str, Any]:
    """
    Reads and parses a YAML file into a Python dictionary.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If YAML parsing fails or is malformed.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        with file_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}  # fallback to empty dict for empty YAML files
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {file_path}: {str(e)}") from e


# Load and return JSON data from a schema file
def load_json(file_path: Path) -> dict[str, Any]:
    """
    Reads and parses a JSON schema file.

    Raises:
        ValueError: If the JSON is malformed.
    """
    try:
        with file_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON schema in {file_path}: {str(e)}") from e


# Validate a Python dictionary (`data`) against a JSON Schema
def validate_schema(data: dict[str, Any], schema_path: Path, label: str) -> None:
    """
    Validates a data structure against a provided JSON schema file.

    Args:
        data: Dictionary to validate.
        schema_path: Path to the schema file.
        label: Human-readable label for logging.
    
    Raises:
        ValidationError: If the data fails validation.
    """
    schema = load_json(schema_path)
    try:
        jsonschema.validate(instance=data, schema=schema)
        logger.info(f"{label} validation passed")
    except jsonschema.exceptions.ValidationError as e:
        raise ValidationError(f"{label} validation failed: {e.message}") from e


# Dynamically parse command-line arguments based on SCHEMA_PLAN
def parse_args() -> argparse.Namespace:
    """
    Constructs an argparse parser based on declared schemas in SCHEMA_PLAN.

    Returns:
        argparse.Namespace containing parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Validate metadata and associated configuration files.")

    # Required args used by all apps
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

    # Optional config files derived from SCHEMA_PLAN
    for key, config in SCHEMA_PLAN.items():
        parser.add_argument(
            f"--{key}-file",
            default="",
            help=f"{config['label']} YAML file under environment directory (e.g., vaultops.yaml)"
        )

    return parser.parse_args()


# Orchestrates the validation logic
def run_validation(args: argparse.Namespace) -> None:
    """
    Core logic for running schema validation on metadata and other config files.

    - Loads metadata file
    - Validates it against its schema
    - Iterates through SCHEMA_PLAN to validate all declared config types

    Merges metadata into config payload if specified by schema config.
    """
    try:
        # Step 1: Validate metadata.yaml (required)
        metadata_path = METADATA_DIR / args.metadata_file
        metadata = load_yaml(metadata_path)
        validate_schema(metadata, SCHEMA_DIR / "metadata.schema.json", "Metadata")

        # Step 2: Loop through all config types (e.g., vaultops, awsops) and validate if passed
        for key, config in SCHEMA_PLAN.items():
            filename = getattr(args, f"{key}_file", "").strip()
            if not filename:
                continue  # Skip if the file argument was not passed

            config_path = Path(args.env_dir) / filename
            config_data = load_yaml(config_path)

            # Some schemas require metadata to be merged into the config (like Vault or AWS)
            payload = {"app": metadata, **config_data} if config.get("merge_with_metadata") else config_data

            schema_path = SCHEMA_DIR / config["schema"]
            validate_schema(payload, schema_path, config["label"])

    # Controlled errors that should exit cleanly
    except (FileNotFoundError, ValueError, ValidationError) as e:
        logger.error(str(e))
        sys.exit(1)

    # Unexpected crash or bug
    except Exception as e:
        logger.exception("Unexpected error occurred during onboarding")
        sys.exit(2)


# Entrypoint wrapper to allow testability
def main() -> None:
    """
    Entrypoint for CLI-based execution.
    """
    args = parse_args()
    run_validation(args)


# If executed as a script (not imported), run the main function
if __name__ == "__main__":
    main()
