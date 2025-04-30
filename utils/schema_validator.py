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
    schema_path = os.path.join(SCHEMA_DIR, f"{schema_name}.schema.yaml")
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    return load_yaml(schema_path)

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
