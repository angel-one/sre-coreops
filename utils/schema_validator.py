import yaml
import json
import os
from typing import Dict
from jsonschema import validate, ValidationError, SchemaError

from utils.logging_utils import setup_logger

logger = setup_logger("schema-validator")

SCHEMA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "schemas"))

def load_yaml(file_path: str) -> Dict:
    with open(file_path, encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_schema(schema_name: str) -> Dict:
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
    logger.info(f"Validating {file_path} against schema '{schema_name}'")
    try:
        data = load_yaml(file_path)
        schema = load_schema(schema_name)
        validate(instance=data, schema=schema)
        logger.info(f"Validation succeeded for {file_path}")
        return True
    except FileNotFoundError as fnf:
        logger.error(fnf)
        raise
    except SchemaError as se:
        logger.error(f"Schema is invalid: {se}")
        raise
    except ValidationError as ve:
        logger.error(f"Validation failed for {file_path}: {ve.message}")
        raise
