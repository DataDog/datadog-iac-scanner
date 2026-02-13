#!/usr/bin/env python3

import sys
import json
import argparse
from pathlib import Path
from copy import deepcopy


NO_DESC = "No description provided"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate documentation from metadata.json and test files"
    )
    parser.add_argument(
        "input_dir", type=Path, help="Base directory containing all the rules"
    )
    return parser.parse_args()


def read_file_contents(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Warning: Failed to read {filepath}: {e}")
        return ""


def load_list(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        sys.exit(f"Error loading providers JSON: {e}")


def process_rule_directory(rule_dir, rule_path, input_dir):
    """Process a single rule directory and update its metadata."""
    metadata_file = rule_dir / "metadata.json"
    if not metadata_file.exists():
        print(f"Skipping {rule_dir.name} — missing metadata.json")
        return

    try:
        with open(metadata_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        provider_url = metadata.get(
            "providerUrl", metadata.get("descriptionUrl", "no-url")
        )
        new_description_url = f"https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/{str(rule_path).lower()}".replace(
            str("assets/queries/"), ""
        )

        new_metadata = deepcopy(metadata)
        new_metadata["descriptionUrl"] = new_description_url
        new_metadata["providerUrl"] = provider_url

        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump(new_metadata, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to parse metadata for {rule_dir}: {e}")


def main():
    args = parse_args()
    input_dir = args.input_dir

    # Check if this directory has providers or rules directly
    # by looking at the first subdirectory to see if it contains metadata.json
    subdirs = [d for d in input_dir.iterdir() if d.is_dir()]
    if not subdirs:
        return

    # Check if first subdirectory has metadata.json (no provider layer)
    first_subdir = subdirs[0]
    has_provider_layer = not (first_subdir / "metadata.json").exists()

    if has_provider_layer:
        # Structure: resource → provider → rule
        for provider in input_dir.iterdir():
            provider_path = provider
            if not provider_path.is_dir():
                print(f"Warning: Missing provider path: {provider_path}")
                continue
            for rule_dir in provider_path.iterdir():
                if not rule_dir.is_dir():
                    continue

                rule_path = provider_path / rule_dir.name
                process_rule_directory(rule_dir, rule_path, input_dir)
    else:
        # Structure: resource → rule (no provider layer)
        for rule_dir in input_dir.iterdir():
            if not rule_dir.is_dir():
                continue

            rule_path = input_dir / rule_dir.name
            process_rule_directory(rule_dir, rule_path, input_dir)


if __name__ == "__main__":
    main()
