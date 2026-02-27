#!/usr/bin/env python3
"""
Validate metadata.json files to ensure they have correct descriptionUrl format.

This script validates that all metadata.json files either:
1. Have descriptionUrls matching the pattern:
   https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/<rule-path-lowercase>
2. OR do not have a providerUrl field

Exit codes:
  0 - All metadata files are valid
  1 - One or more metadata files are invalid
"""

import argparse
import glob
import json
import os
import re
import sys
from typing import List, Dict, Tuple


def find_metadata_files(base_path: str, include_tests: bool = False) -> List[str]:
    """
    Find all metadata.json files in the repository.

    Args:
        base_path: Base directory to search from
        include_tests: Whether to include test/fixture metadata files

    Returns:
        List of paths to metadata.json files
    """
    pattern = os.path.join(base_path, "**/metadata.json")
    all_files = glob.glob(pattern, recursive=True)

    if not include_tests:
        # Filter out test and fixture files
        all_files = [
            f for f in all_files if "/test/" not in f and "/fixtures/" not in f
        ]

    return all_files


def extract_rule_path_from_file(file_path: str, base_path: str) -> str:
    """
    Extract the rule path from the file path.

    For example:
    /path/to/assets/queries/cloudFormation/aws/api_gateway_with_open_access/metadata.json
    -> cloudformation/aws/api_gateway_with_open_access

    Args:
        file_path: Full path to the metadata.json file
        base_path: Base path of the repository

    Returns:
        The rule path in lowercase
    """
    # Get relative path from base
    rel_path = os.path.relpath(file_path, base_path)

    # Extract the part after assets/queries/
    if "assets/queries/" in rel_path:
        parts = rel_path.split("assets/queries/")[1]
        # Remove /metadata.json from the end
        parts = parts.replace("/metadata.json", "")
        # Convert to lowercase
        return parts.lower()

    return ""


def validate_description_url(
    description_url: str, expected_path: str
) -> Tuple[bool, str]:
    """
    Validate that the descriptionUrl matches the expected pattern.

    Args:
        description_url: The descriptionUrl from metadata.json
        expected_path: The expected rule path (lowercase)

    Returns:
        Tuple of (is_valid, error_message)
    """
    expected_prefix = (
        "https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/"
    )

    if not description_url:
        return False, "descriptionUrl is empty or missing"

    if not description_url.startswith(expected_prefix):
        return (
            False,
            f"descriptionUrl does not start with expected prefix: {expected_prefix}",
        )

    # Extract the path part from the URL
    url_path = description_url.replace(expected_prefix, "")

    # Check if the path matches (case-insensitive)
    if url_path.lower() != expected_path.lower():
        return (
            False,
            f"descriptionUrl path '{url_path}' does not match expected path '{expected_path}'",
        )

    # Check that the URL path is all lowercase
    if url_path != url_path.lower():
        return False, f"descriptionUrl path must be lowercase, got: {url_path}"

    return True, ""


def validate_metadata_file(
    file_path: str, base_path: str, verbose: bool = False
) -> Tuple[bool, List[str]]:
    """
    Validate a single metadata.json file.

    Args:
        file_path: Path to the metadata.json file
        base_path: Base path of the repository
        verbose: Whether to print verbose output

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {e}")
        return False, errors
    except Exception as e:
        errors.append(f"Error reading file: {e}")
        return False, errors

    description_url = metadata.get("descriptionUrl", "")
    has_provider_url = "providerUrl" in metadata

    # Rule: Either descriptionUrl matches pattern OR there's no providerUrl
    # This means a file is INVALID if it has a providerUrl AND descriptionUrl doesn't match

    if has_provider_url:
        # If providerUrl exists, descriptionUrl MUST match the pattern
        expected_path = extract_rule_path_from_file(file_path, base_path)

        if not expected_path:
            errors.append("Could not extract rule path from file location")
            return False, errors

        is_valid, error_msg = validate_description_url(description_url, expected_path)

        if not is_valid:
            errors.append(f"Has providerUrl but descriptionUrl is invalid: {error_msg}")
            errors.append(
                f"  Expected: https://docs.datadoghq.com/security/code_security/iac_security/iac_rules/{expected_path}"
            )
            errors.append(f"  Got: {description_url}")
            return False, errors

    # If no providerUrl, validation passes regardless of descriptionUrl
    # If has providerUrl, we already checked descriptionUrl above

    return True, []


def main():
    parser = argparse.ArgumentParser(
        description="Validate metadata.json files for correct descriptionUrl format"
    )
    parser.add_argument(
        "-b",
        "--base-path",
        type=str,
        default=".",
        help="Base path of the repository (default: current directory)",
    )
    parser.add_argument(
        "-t",
        "--include-tests",
        action="store_true",
        default=False,
        help="Include test and fixture metadata files in validation",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Verbose output"
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Specific metadata.json files to validate (optional, if not provided, all files are validated)",
    )

    args = parser.parse_args()

    # Get list of files to validate
    if args.files:
        metadata_files = args.files
    else:
        metadata_files = find_metadata_files(args.base_path, args.include_tests)

    if not metadata_files:
        print("No metadata.json files found")
        return 0

    print(f"Validating {len(metadata_files)} metadata.json files...")

    invalid_files = []
    valid_count = 0

    for file_path in metadata_files:
        if args.verbose:
            print(f"\nChecking: {file_path}")
        else:
            print(".", end="", flush=True)

        is_valid, errors = validate_metadata_file(
            file_path, args.base_path, args.verbose
        )

        if is_valid:
            valid_count += 1
            if args.verbose:
                print("  ✓ Valid")
        else:
            invalid_files.append({"file": file_path, "errors": errors})

    print("\n")
    print("=" * 80)
    print(f"Validation Summary:")
    print(f"  Total files checked: {len(metadata_files)}")
    print(f"  Valid: {valid_count}")
    print(f"  Invalid: {len(invalid_files)}")
    print("=" * 80)

    if invalid_files:
        print("\nInvalid files found:\n")
        for item in invalid_files:
            print(f"✗ {item['file']}")
            for error in item["errors"]:
                print(f"  {error}")
            print()

        return 1

    print("\n✓ All metadata files are valid!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
