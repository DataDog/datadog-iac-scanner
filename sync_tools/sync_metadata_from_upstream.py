#!/usr/bin/env python3
"""
Sync metadata fields from upstream Checkmarx KICS repository to Datadog fork.

This script:
1. Finds all metadata.json files with empty or missing field values
2. Fetches the corresponding metadata.json from upstream Checkmarx repo
3. Updates specified fields if upstream has values
4. Preserves all other Datadog-specific fields (like descriptionText, descriptionUrl)

Commonly synced fields: cwe, queryURI, aggregation, etc.
"""

import json
import os
import sys
from pathlib import Path
import urllib.request
import urllib.error
from typing import Dict, Optional

# Configuration
UPSTREAM_BASE_URL = "https://raw.githubusercontent.com/Checkmarx/kics/master/"
QUERIES_DIR = "assets/queries"

# Statistics
stats = {
    "total_checked": 0,
    "empty_field": 0,
    "updated": 0,
    "not_found_upstream": 0,
    "upstream_also_empty": 0,
    "errors": 0,
}


def fetch_upstream_metadata(relative_path: str) -> Optional[Dict]:
    """Fetch metadata.json from upstream Checkmarx repo."""
    url = UPSTREAM_BASE_URL + relative_path
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = response.read().decode('utf-8')
            return json.loads(data)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        print(f"  ⚠️  HTTP Error {e.code} for {relative_path}")
        return None
    except Exception as e:
        print(f"  ⚠️  Error fetching {relative_path}: {e}")
        return None


def update_field_from_upstream(metadata_path: Path, field_name: str, dry_run: bool = False) -> bool:
    """
    Update specified field in metadata.json from upstream if empty.

    Args:
        metadata_path: Path to local metadata.json file
        field_name: Name of the field to sync (e.g., 'cwe', 'queryURI', 'aggregation')
        dry_run: If True, only preview changes without modifying files

    Returns True if updated, False otherwise.
    """
    stats["total_checked"] += 1

    # Read local metadata
    try:
        with open(metadata_path, 'r', encoding='utf-8') as f:
            local_metadata = json.load(f)
    except Exception as e:
        print(f"  ❌ Error reading {metadata_path}: {e}")
        stats["errors"] += 1
        return False

    # Check if field is empty or missing
    local_value = local_metadata.get(field_name, "")
    if local_value and str(local_value).strip():
        # Already has value, skip
        return False

    stats["empty_field"] += 1

    # Get relative path from repo root
    try:
        relative_path = str(metadata_path.relative_to(Path.cwd()))
    except ValueError:
        # Handle absolute paths
        relative_path = str(metadata_path.resolve().relative_to(Path.cwd().resolve()))

    # Fetch upstream metadata
    print(f"  🔍 Checking: {relative_path}")
    upstream_metadata = fetch_upstream_metadata(relative_path)

    if upstream_metadata is None:
        print(f"  ⚠️  Not found in upstream")
        stats["not_found_upstream"] += 1
        return False

    # Get upstream field value
    upstream_value = upstream_metadata.get(field_name, "")
    if not upstream_value or not str(upstream_value).strip():
        print(f"  ℹ️  Upstream also has empty {field_name}")
        stats["upstream_also_empty"] += 1
        return False

    # Update local metadata with upstream value
    local_metadata[field_name] = upstream_value
    print(f"  ✅ {field_name}: {upstream_value}")

    if not dry_run:
        # Write updated metadata
        try:
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(local_metadata, f, indent=2, ensure_ascii=False)
                f.write('\n')  # Add trailing newline
            stats["updated"] += 1
            return True
        except Exception as e:
            print(f"  ❌ Error writing {metadata_path}: {e}")
            stats["errors"] += 1
            return False
    else:
        print(f"  🔸 [DRY RUN] Would update {field_name} to: {upstream_value}")
        stats["updated"] += 1
        return True


def find_metadata_files() -> list[Path]:
    """Find all metadata.json files in queries directory."""
    queries_path = Path(QUERIES_DIR)
    if not queries_path.exists():
        print(f"❌ Queries directory not found: {QUERIES_DIR}")
        sys.exit(1)

    return list(queries_path.rglob("metadata.json"))


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Sync metadata fields from upstream Checkmarx KICS repository",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run (preview changes)
  python sync_cwe_from_upstream.py --field cwe --dry-run

  # Update all empty CWE values
  python sync_cwe_from_upstream.py --field cwe

  # Update queryURI for CloudFormation rules
  python sync_cwe_from_upstream.py --field queryURI --platform cloudFormation

  # Update aggregation field for AWS CloudFormation rules
  python sync_cwe_from_upstream.py --field aggregation --platform cloudFormation --provider aws
        """
    )

    parser.add_argument(
        "--field",
        type=str,
        default="cwe",
        help="Field name to sync from upstream (default: cwe). Common fields: cwe, queryURI, aggregation"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying files"
    )

    parser.add_argument(
        "--platform",
        type=str,
        help="Filter by platform (e.g., cloudFormation, terraform, k8s)"
    )

    parser.add_argument(
        "--provider",
        type=str,
        help="Filter by cloud provider (e.g., aws, azure, gcp)"
    )

    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of files to process (for testing)"
    )

    args = parser.parse_args()

    print("=" * 80)
    print(f"🔄 Syncing '{args.field}' field from upstream Checkmarx KICS")
    print("=" * 80)

    if args.dry_run:
        print("🔸 DRY RUN MODE - No files will be modified")
        print()

    # Find all metadata files
    print(f"📂 Scanning for metadata.json files in {QUERIES_DIR}...")
    metadata_files = find_metadata_files()

    # Apply filters
    if args.platform:
        metadata_files = [
            f for f in metadata_files
            if args.platform.lower() in str(f).lower()
        ]
        print(f"🔍 Filtered to platform: {args.platform}")

    if args.provider:
        metadata_files = [
            f for f in metadata_files
            if args.provider.lower() in str(f).lower()
        ]
        print(f"🔍 Filtered to provider: {args.provider}")

    if args.limit:
        metadata_files = metadata_files[:args.limit]
        print(f"🔍 Limited to first {args.limit} files")

    print(f"📊 Found {len(metadata_files)} metadata.json files")
    print()

    # Process each file
    for metadata_path in metadata_files:
        update_field_from_upstream(metadata_path, args.field, dry_run=args.dry_run)

    # Print statistics
    print()
    print("=" * 80)
    print("📊 SUMMARY")
    print("=" * 80)
    print(f"Field synced:              '{args.field}'")
    print(f"Total files checked:       {stats['total_checked']}")
    print(f"Files with empty field:    {stats['empty_field']}")
    print(f"✅ Successfully updated:   {stats['updated']}")
    print(f"⚠️  Not found in upstream:  {stats['not_found_upstream']}")
    print(f"ℹ️  Upstream also empty:    {stats['upstream_also_empty']}")
    print(f"❌ Errors:                 {stats['errors']}")
    print("=" * 80)

    if args.dry_run:
        print()
        print("🔸 This was a DRY RUN. Run without --dry-run to apply changes.")
    elif stats['updated'] > 0:
        print()
        print(f"✅ Field '{args.field}' has been updated in {stats['updated']} files!")
        print("💡 Next steps:")
        print("   1. Review changes: git diff assets/queries")
        print(f"   2. Commit changes: git add assets/queries && git commit -m 'Sync {args.field} from upstream'")


if __name__ == "__main__":
    main()

