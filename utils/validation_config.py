from pathlib import Path

SCHEMA_PLAN = {
    "vaultops": {
        "label": "VaultOps",
        "schema": "vaultops.schema.json",
        "merge_with_metadata": True,
    },
    "awsops": {
        "label": "AWSOps",
        "schema": "awsops.schema.json",
        "merge_with_metadata": True,
    },
    "consulops": {
        "label": "ConsulOps",
        "schema": "consulops.schema.json",
        "merge_with_metadata": True,
    },
    # Add more here when needed
}
