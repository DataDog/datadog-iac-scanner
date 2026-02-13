#!/usr/bin/env python3
"""
Script to sync framework mappings for IAC rules from security-monitoring repository.

This script extracts iacRules mappings from framework TOML files and creates
corresponding metadata.json files in the current KICS repository.

The frameworks are sourced from:
- posture-management-test/frameworks (higher priority)
- posture-management/frameworks/production (lower priority)

Usage:
    python sync_framework_mappings.py --source ~/dd/security-monitoring
"""

import argparse
import json
import os
import sys
from pathlib import Path
import toml
from collections import defaultdict


def find_framework_files_with_iac_rules(frameworks_dir):
    """Find all TOML files containing iacRules in the frameworks directory."""
    toml_files = []

    for root, dirs, files in os.walk(frameworks_dir):
        for file in files:
            if file.endswith('.toml'):
                filepath = Path(root) / file
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if 'iacRules' in content:
                            toml_files.append(filepath)
                except Exception as e:
                    print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)

    return toml_files


def get_framework_name_from_config(toml_file):
    """Get framework name from framework group config file."""
    # Look for framework group config file in the same directory or parent directories
    current_dir = toml_file.parent

    # Check up to 3 levels up for framework group config
    for _ in range(3):
        group_file = current_dir / f"{current_dir.name}_group.toml"
        if group_file.exists():
            try:
                with open(group_file, 'r') as f:
                    group_data = toml.load(f)
                return group_data.get('framework', current_dir.name)
            except Exception:
                pass
        current_dir = current_dir.parent
        if current_dir.name == 'frameworks':
            break

    return None


def extract_iac_rules_mappings(toml_file):
    """Extract iacRules mappings from a TOML framework file."""
    mappings = []

    try:
        with open(toml_file, 'r') as f:
            data = toml.load(f)

        # Determine framework name from path structure
        framework_path = str(toml_file.relative_to(toml_file.parents[4]))  # relative to frameworks/

        # Try to get framework name from multiple sources in order of preference:
        # 1. Direct 'framework' field in the TOML data
        framework_name = data.get('framework')

        # 2. Framework name from group config file
        if not framework_name:
            framework_name = get_framework_name_from_config(toml_file)

        # 3. Fallback to filename for other frameworks
        if not framework_name:
            framework_name = toml_file.stem

        # Get requirement from TOML data if available, convert to lowercase
        requirement = data.get('requirement', toml_file.stem).lower()

        # Extract version from TOML data or metadata.toml file and prepend 'v'
        version = data.get('version')

        # If no version in main TOML, check for metadata.toml in same directory
        if not version:
            metadata_file = toml_file.parent / 'metadata.toml'
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r') as f:
                        metadata_data = toml.load(f)
                    version = metadata_data.get('version')
                except Exception:
                    pass

        # Default to '1' if still no version found
        if not version:
            version = '1'

        framework_version = f"v{version}"

        for section_key, section_data in data.items():
            if isinstance(section_data, dict) and 'iacRules' in section_data:
                control = section_data.get('control', section_key)
                description = section_data.get('description', '')

                for iac_rule in section_data['iacRules']:
                    mappings.append({
                        'framework': framework_name,
                        'framework_path': framework_path,
                        'framework_version': framework_version,
                        'control': control,
                        'description': description,
                        'iac_rule': iac_rule,
                        'section': section_key,
                        'requirement': requirement
                    })
    except Exception as e:
        print(f"Error parsing {toml_file}: {e}", file=sys.stderr)

    return mappings


def scan_existing_framework_mappings(kics_dir, target_framework="essential-cloud-security-controls"):
    """Scan existing metadata.json files to find current framework mappings."""
    existing_mappings = {}  # iac_rule_path -> set of frameworks

    assets_dir = kics_dir / 'assets' / 'queries'
    if not assets_dir.exists():
        return existing_mappings

    # Find all metadata.json files
    for metadata_path in assets_dir.rglob('metadata.json'):
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # Extract the relative path from assets/queries/
            relative_path = metadata_path.parent.relative_to(assets_dir)
            iac_rule_path = f"assets/queries/{relative_path}"

            # Check if this file has framework mappings for our target framework
            default_frameworks = metadata.get('defaultFrameworks', [])
            frameworks = {fw.get('framework') for fw in default_frameworks
                         if fw.get('framework') == target_framework}

            if frameworks:
                existing_mappings[iac_rule_path] = frameworks

        except Exception as e:
            # Silently skip files that can't be read/parsed
            continue

    return existing_mappings


def cleanup_orphaned_mappings(kics_dir, existing_mappings, current_mappings, target_framework="essential-cloud-security-controls", dry_run=False):
    """Remove framework mappings from rules that no longer have iacRules."""
    orphaned_rules = set(existing_mappings.keys()) - set(current_mappings.keys())
    cleanup_count = 0

    for orphaned_rule in orphaned_rules:
        rule_path = kics_dir / 'assets' / 'queries' / orphaned_rule.replace('assets/queries/', '')
        metadata_path = rule_path / 'metadata.json'

        if not metadata_path.exists():
            continue

        try:
            # Read existing metadata
            with open(metadata_path, 'r') as f:
                original_content = f.read()
                metadata = json.loads(original_content)

            # Remove target framework from defaultFrameworks
            original_frameworks = metadata.get('defaultFrameworks', [])
            filtered_frameworks = [
                fw for fw in original_frameworks
                if fw.get('framework') != target_framework
            ]

            # Only update if something was actually removed
            if len(filtered_frameworks) != len(original_frameworks):
                if dry_run:
                    print(f"DRY RUN: Would remove {target_framework} mapping from {metadata_path}")
                else:
                    # If no frameworks left, remove the property entirely
                    if filtered_frameworks:
                        metadata['defaultFrameworks'] = filtered_frameworks
                    else:
                        metadata.pop('defaultFrameworks', None)

                    # Write updated metadata preserving formatting
                    with open(metadata_path, 'w') as f:
                        json.dump(metadata, f, indent=2, separators=(',', ': '), ensure_ascii=True)
                    print(f"Cleaned up {metadata_path}")

                cleanup_count += 1

        except Exception as e:
            print(f"Error cleaning up {metadata_path}: {e}", file=sys.stderr)

    return cleanup_count


def update_metadata_file(iac_rule_path, framework_mappings, dry_run=False):
    """Update the metadata.json file for an iacRule path with framework mappings."""
    metadata_path = Path(iac_rule_path) / 'metadata.json'

    # Read existing metadata
    metadata = {}
    original_content = ""
    if metadata_path.exists():
        try:
            with open(metadata_path, 'r') as f:
                original_content = f.read()
                metadata = json.loads(original_content)
        except Exception as e:
            print(f"Warning: Could not read existing {metadata_path}: {e}", file=sys.stderr)

    # Completely replace defaultFrameworks with new mappings from sync
    new_default_frameworks = []

    # Add new mappings
    for mapping in framework_mappings:
        new_default_frameworks.append({
            'control': mapping['control'],
            'framework': mapping['framework'],
            'framework_version': mapping['framework_version'],  # Using version from TOML data or path
            'requirement': mapping['requirement']  # Using requirement from TOML file
        })

    # Replace the entire defaultFrameworks field, or remove if empty
    if new_default_frameworks:
        metadata['defaultFrameworks'] = new_default_frameworks
    else:
        metadata.pop('defaultFrameworks', None)

    if dry_run:
        print(f"DRY RUN: Would update {metadata_path}")
        print(f"  Default frameworks: {len(new_default_frameworks)}")
        return True

    # Write updated metadata preserving original formatting as much as possible
    try:
        os.makedirs(metadata_path.parent, exist_ok=True)

        # Try to preserve original formatting by using same indent/separators
        indent = 2
        separators = (',', ': ')
        if original_content:
            # Try to detect original formatting
            lines = original_content.split('\n')
            if len(lines) > 1 and lines[1].startswith('  '):
                # Count leading spaces to determine indent
                for line in lines[1:]:
                    if line.strip() and not line.startswith(' '):
                        break
                    if line.strip():
                        indent = len(line) - len(line.lstrip())
                        break

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=indent, separators=separators, ensure_ascii=True)
        print(f"Updated {metadata_path}")
        return True
    except Exception as e:
        print(f"Error writing {metadata_path}: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Sync framework mappings for IAC rules from security-monitoring repository'
    )
    parser.add_argument(
        '--source',
        default=os.path.expanduser('~/dd/security-monitoring'),
        help='Path to security-monitoring repository (default: ~/dd/security-monitoring)'
    )
    parser.add_argument(
        '--kics-dir',
        default='../',
        help='Path to KICS repository directory (default: ../)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    source_dir = Path(args.source)
    if not source_dir.exists():
        print(f"Error: Source directory {source_dir} does not exist", file=sys.stderr)
        return 1

    kics_dir = Path(args.kics_dir)
    if not kics_dir.exists():
        print(f"Error: KICS directory {kics_dir} does not exist", file=sys.stderr)
        return 1

    # Framework directories in priority order (test takes precedence)
    framework_dirs = [
        source_dir / 'posture-management-test' / 'frameworks',
        source_dir / 'posture-management' / 'frameworks' / 'production'
    ]

    # Collect all iacRules mappings
    all_mappings = defaultdict(list)  # iac_rule_path -> [mappings]
    processed_frameworks = set()  # Track which frameworks we've already processed from high-priority dirs

    for frameworks_dir in framework_dirs:
        if not frameworks_dir.exists():
            if args.verbose:
                print(f"Skipping non-existent directory: {frameworks_dir}")
            continue

        print(f"Processing frameworks in {frameworks_dir}")

        toml_files = find_framework_files_with_iac_rules(frameworks_dir)
        if args.verbose:
            print(f"Found {len(toml_files)} TOML files with iacRules")

        is_test_dir = 'posture-management-test' in str(frameworks_dir)

        for toml_file in toml_files:
            mappings = extract_iac_rules_mappings(toml_file)
            if args.verbose and mappings:
                print(f"  {toml_file.name}: {len(mappings)} iacRules mappings")

            # Get the framework name to check for duplicates
            framework_name = None
            if mappings:
                framework_name = mappings[0]['framework']

            # Skip if we already processed this framework from a higher priority directory
            if not is_test_dir and framework_name in processed_frameworks:
                if args.verbose:
                    print(f"  Skipping {framework_name} from production (already processed from test)")
                continue

            # Add mappings and track the framework
            for mapping in mappings:
                iac_rule_path = mapping['iac_rule']
                all_mappings[iac_rule_path].append(mapping)

            # Track processed frameworks from high-priority directories
            if is_test_dir and framework_name:
                processed_frameworks.add(framework_name)

    # Scan existing metadata files for cleanup
    if args.verbose:
        print("Scanning existing framework mappings for cleanup...")
    existing_mappings = scan_existing_framework_mappings(kics_dir)

    # Clean up orphaned mappings (rules that no longer have iacRules)
    cleanup_count = cleanup_orphaned_mappings(kics_dir, existing_mappings, all_mappings, dry_run=args.dry_run)

    # Update metadata files
    updated_count = 0
    error_count = 0

    for iac_rule_path, mappings in all_mappings.items():
        local_path = kics_dir / 'assets' / 'queries' / iac_rule_path.replace('assets/queries/', '')

        if not local_path.exists() and not args.dry_run:
            print(f"Warning: Local path does not exist: {local_path}", file=sys.stderr)
            error_count += 1
            continue

        if update_metadata_file(local_path, mappings, args.dry_run):
            updated_count += 1
        else:
            error_count += 1

    print(f"\nSummary:")
    print(f"  Processed {len(all_mappings)} iacRules")
    print(f"  Updated {updated_count} metadata files")
    if cleanup_count:
        print(f"  Cleaned up {cleanup_count} orphaned mappings")
    if error_count:
        print(f"  Errors: {error_count}")

    return 0 if error_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())