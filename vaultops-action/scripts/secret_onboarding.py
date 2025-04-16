import os
import sys
import yaml
import json
import jsonschema

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SCHEMA_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "schemas"))

def load_yaml(path, name):
    full_path = os.path.join(path, name)
    if not os.path.isfile(full_path):
        print(f"❌ File not found: {full_path}")
        sys.exit(1)
    with open(full_path, "r") as f:
        return yaml.safe_load(f)

def validate_schema(data, schema_path, label):
    with open(schema_path, "r") as f:
        schema = json.load(f)
    try:
        jsonschema.validate(instance=data, schema=schema)
        print(f"✅ {label} validation passed.")
    except jsonschema.exceptions.ValidationError as e:
        print(f"❌ {label} validation failed:\n{e.message}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python secret_onboarding.py <env_dir> <metadata_file> <vaultops_file?> <nomadops_file?>")
        sys.exit(1)

    env_dir        = sys.argv[1]
    metadata_file  = sys.argv[2]
    vaultops_file  = sys.argv[3]
    nomadops_file  = sys.argv[4] if len(sys.argv) > 4 else ""

    # Validate metadata
    metadata_path = os.path.join("coreops", "metadata")
    metadata = load_yaml(metadata_path, metadata_file)
    validate_schema(metadata, os.path.join(SCHEMA_DIR, "metadata.schema.json"), "Metadata")

    # Validate vaultops if present
    if vaultops_file:
        vaultops = load_yaml(env_dir, vaultops_file)
        merged_vault = {
            "app": metadata,
            **vaultops
        }
        validate_schema(merged_vault, os.path.join(SCHEMA_DIR, "vaultops.schema.json"), "VaultOps")

    # Validate nomadops if present
    if nomadops_file:
        nomadops = load_yaml(env_dir, nomadops_file)
        merged_nomad = {
            "app": metadata,
            **nomadops
        }
        validate_schema(merged_nomad, os.path.join(SCHEMA_DIR, "nomadops.schema.json"), "NomadOps")
