import yaml
import json
import os
from typing import Dict
from jsonschema import validate, ValidationError, SchemaError

# Import the setup_logger function from utils
from utils.logging_utils import setup_logger

# Initialize the logger for schema validation
logger = setup_logger("schema-validator")

# Define the directory where schema files are located
SCHEMA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "schemas"))

def load_yaml(file_path: str) -> Dict:
    """
    Reads a YAML file from the given file path and returns its contents as a dictionary.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        Dict: The parsed YAML content as a dictionary.
    """
    with open(file_path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_schema(schema_name: str) -> Dict:
    """
    Loads a schema file (JSON or YAML) by name from the SCHEMA_DIR.

    Args:
        schema_name (str): The base name of the schema file to load (without extension).

    Returns:
        Dict: The loaded schema as a dictionary.

    Raises:
        FileNotFoundError: If no schema file is found for the given name.
    """
    for ext in ("json", "yaml", "yml"):
        schema_path = os.path.join(SCHEMA_DIR, f"{schema_name}.schema.{ext}")
        if os.path.exists(schema_path):
            with open(schema_path, encoding="utf-8") as f:
                if ext == "json":
                    return json.load(f)
                else:
                    return yaml.safe_load(f)
    raise FileNotFoundError(f"No schema found for '{schema_name}' with .json/.yaml/.yml extension in {SCHEMA_DIR}")

def validate_yaml(file_path: str, schema_name: str) -> bool:
    """
    Validates a YAML file against a specified schema.

    Args:
        file_path (str): The path to the YAML file to validate.
        schema_name (str): The name of the schema to validate against.

    Returns:
        bool: True if the file is valid against the schema, False otherwise.
    """
    logger.info(f"Validating {file_path} against schema '{schema_name}'")
    try:
        # Load the YAML file and the schema
        data = load_yaml(file_path)
        schema = load_schema(schema_name)
        
        # Validate the YAML data against the schema
        validate(instance=data, schema=schema)
        logger.info(f"{file_path} is valid against schema '{schema_name}'")
        return True
    except (ValidationError, SchemaError) as e:
        logger.error(f"Validation error for {file_path}: {e}")
        return False