import os
import sys
import json
import yaml
import jsonschema
from jsonschema import validate

SCHEMA_FILE = ".github/actions/vaultops/schema/onboarding.schema.json"

def load_yaml(directory, filename):
    path = os.path.join(directory, filename)
    with open(path, "r") as f:
        return yaml.safe_load(f)

def load_schema():
    with open(SCHEMA_FILE, "r") as f:
        return json.load(f)

def validate_yaml(data, schema):
    try:
        validate(instance=data, schema=schema)
        print("✅ YAML schema validation passed.")
    except jsonschema.exceptions.ValidationError as e:
        print("❌ YAML schema validation failed:")
        print(e.message)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python secret_onboarding.py <directory> <filename>")
        sys.exit(1)

    directory, filename = sys.argv[1], sys.argv[2]

    yaml_data = load_yaml(directory, filename)
    schema = load_schema()
    validate_yaml(yaml_data, schema)
