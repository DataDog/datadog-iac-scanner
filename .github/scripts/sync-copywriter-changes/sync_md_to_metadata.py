#!/usr/bin/env python3
"""
Sync copywriter changes from markdown documentation files back to metadata.json.

This script parses markdown files with YAML frontmatter and updates the corresponding
metadata.json files in the assets/queries directory structure.

Designed to be reusable for both CLI execution and GitHub Actions integration.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def extract_informations_from_md(
    content: str,
) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Extract the informations from markdown content.

    Args:
        content: Markdown content (full file including frontmatter)

    Returns:
        Query name, description, severity and category
    """

    # Extract query name from title in frontmatter
    query_name = None
    query_name_pattern = r'title:\s*"([^"]+)"'
    query_name_match = re.search(query_name_pattern, content)

    if query_name_match:
        query_name = query_name_match.group(1).strip()

    # Look for ### Description heading and capture until ## (next section)
    description = None
    description_pattern = r"### Description\s*\n\s*\n(.*?)(?=\n## )"
    description_match = re.search(description_pattern, content, re.DOTALL)

    if description_match:
        description = description_match.group(1).strip()
        # Clean up extra whitespace but preserve single newlines
        description = re.sub(r"\n{3,}", "\n\n", description)

    # Extract severity from meta section in frontmatter
    severity = None
    severity_pattern = r'severity:\s*"([^"]+)"'
    severity_match = re.search(severity_pattern, content)

    if severity_match:
        severity = severity_match.group(1).strip()

    # Extract category from meta section in frontmatter
    category = None
    category_pattern = r'category:\s*"([^"]+)"'
    category_match = re.search(category_pattern, content)

    if category_match:
        category = category_match.group(1).strip()

    return query_name, description, severity, category


def find_json_paths(
    md_file_path: Path, assets_queries_dir: Path
) -> tuple[Optional[Path], Optional[Path]]:
    """
    Find the corresponding metadata.json and positive_expected_result.json files for a given markdown file.

    The structure is:
    - documentation/rules/{platform}/{provider}/{rule_name}.md
    - assets/queries/{platform}/{provider}/{rule_name}/metadata.json
    - assets/queries/{platform}/{provider}/{rule_name}/test/positive_expected_result.json

    Args:
        md_file_path: Path to the markdown documentation file
        assets_queries_dir: Path to the assets/queries directory

    Returns:
        Path to metadata.json or None if not found, Path to positive_expected_result.json or None if not found
    """
    # Get relative path from documentation/rules/
    # Expected: documentation/rules/{platform}/{provider}/{rule_name}.md
    parts = md_file_path.parts

    # Find 'rules' in the path
    try:
        rules_idx = parts.index("rules")
    except ValueError:
        return None

    # Extract platform/provider/rule_name
    relative_parts = parts[rules_idx + 1 :]

    if len(relative_parts) < 2:
        return None

    # Remove .md extension from the last part (rule name)
    rule_name = relative_parts[-1].replace(".md", "")

    # Construct metadata.json path
    metadata_path = (
        assets_queries_dir / Path(*relative_parts[:-1]) / rule_name / "metadata.json"
    )

    positive_expected_result_path = (
        assets_queries_dir
        / Path(*relative_parts[:-1])
        / rule_name
        / "test"
        / "positive_expected_result.json"
    )

    return metadata_path if metadata_path.exists() else None, (
        positive_expected_result_path
        if positive_expected_result_path.exists()
        else None
    )


def update_metadata_json(
    metadata_path: Path,
    query_name: str | None,
    description: str | None,
    severity: str | None,
    category: str | None,
    dry_run: bool = False,
) -> bool:
    """
    Update metadata.json file with data from markdown.

    Args:
        metadata_path: Path to metadata.json file
        query_name: Extracted query name
        description: Extracted description text
        severity: Extracted severity
        category: Extracted category
        dry_run: If True, only show what would change without writing

    Returns:
        True if changes were made (or would be made in dry-run), False otherwise
    """
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading {metadata_path}: {e}", file=sys.stderr)
        return False

    changes = []

    # Update query name
    if query_name and metadata.get("queryName") != query_name:
        new_query_name = metadata.get("queryName", "")
        changes.append(f"  queryName: '{new_query_name}' -> '{query_name}'")
        if not dry_run:
            metadata["queryName"] = query_name

    # Update description text
    if description and metadata.get("descriptionText") != description:
        old_desc_preview = metadata.get("descriptionText", "")[:60] + "..."
        new_desc_preview = description[:60] + "..."
        changes.append(
            f"  descriptionText: '{old_desc_preview}' -> '{new_desc_preview}'"
        )
        if not dry_run:
            metadata["descriptionText"] = description

    # Update severity
    if severity and metadata.get("severity") != severity:
        new_severity = metadata.get("severity", "")
        changes.append(f"  severity: '{new_severity}' -> '{severity}'")
        if not dry_run:
            metadata["severity"] = severity

    # Update category
    if category and metadata.get("category") != category:
        new_category = metadata.get("category", "")
        changes.append(f"  category: '{new_category}' -> '{category}'")
        if not dry_run:
            metadata["category"] = category

    if changes:
        print(f"\n{'[DRY RUN] ' if dry_run else ''}Updating {metadata_path}:")
        for change in changes:
            print(change)

        if not dry_run:
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
                f.write("\n")  # Add trailing newline

        return True

    return False


def update_positive_expected_result_json(
    positive_expected_result_path: Path,
    query_name: str | None,
    severity: str | None,
    dry_run: bool = False,
) -> bool:
    """
    Update positive_expected_result.json file with data from markdown.

    Args:
        metadata_path: Path to metadata.json file
        query_name: Extracted query name
        severity: Extracted severity
        dry_run: If True, only show what would change without writing

    Returns:
        True if changes were made (or would be made in dry-run), False otherwise
    """
    try:
        with open(positive_expected_result_path, "r", encoding="utf-8") as f:
            positive_expected_results = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading {positive_expected_result_path}: {e}", file=sys.stderr)
        return False

    changes = []

    for i in range(len(positive_expected_results)):
        # Update query name
        if query_name and positive_expected_results[i]["queryName"] != query_name:
            new_query_name = positive_expected_results[i]["queryName"]
            changes.append(f"  queryName: '{new_query_name}' -> '{query_name}'")
            if not dry_run:
                positive_expected_results[i]["queryName"] = query_name

        # Update severity
        if severity and positive_expected_results[i]["severity"] != severity:
            new_severity = positive_expected_results[i]["severity"]
            changes.append(f"  severity: '{new_severity}' -> '{severity}'")
            if not dry_run:
                positive_expected_results[i]["severity"] = severity

    if changes:
        print(
            f"\n{'[DRY RUN] ' if dry_run else ''}Updating {positive_expected_result_path}:"
        )
        for change in changes:
            print(change)

        if not dry_run:
            with open(positive_expected_result_path, "w", encoding="utf-8") as f:
                json.dump(positive_expected_results, f, indent=2, ensure_ascii=False)
                f.write("\n")  # Add trailing newline

        return True

    return False


def sync_md_to_metadata(
    md_dir: Path,
    assets_queries_dir: Path,
    specific_files: Optional[List[str]] = None,
    dry_run: bool = False,
    verbose: bool = False,
) -> Tuple[int, int, int]:
    """
    Sync markdown documentation files to metadata.json files.

    Args:
        md_dir: Path to documentation/rules directory
        assets_queries_dir: Path to assets/queries directory
        specific_files: Optional list of specific MD files to process
        dry_run: If True, show what would change without making changes
        verbose: If True, show detailed processing information

    Returns:
        Tuple of (processed_count, updated_count, error_count)
    """
    processed = 0
    updated = 0
    errors = 0

    # Get list of markdown files to process
    if specific_files:
        md_files = [Path(f) for f in specific_files if Path(f).suffix == ".md"]
    else:
        md_files = list(md_dir.rglob("*.md"))

    for md_file in md_files:
        if verbose:
            print(f"\nProcessing: {md_file}")

        processed += 1

        try:
            # Read markdown file
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract information from full markdown content
            name, description, severity, category = extract_informations_from_md(
                content
            )

            # Find corresponding metadata.json
            metadata_path, positive_expected_result_path = find_json_paths(
                md_file, assets_queries_dir
            )

            if not metadata_path:
                if verbose:
                    print(f"  No corresponding metadata.json found")
                continue

            if not positive_expected_result_path:
                if verbose:
                    print(f"  No corresponding positive_expected_result.json found")
                continue

            # Update metadata.json and positive_expected_result.json
            metadata_updated = update_metadata_json(
                metadata_path,
                name,
                description,
                severity,
                category,
                dry_run,
            )
            positive_updated = update_positive_expected_result_json(
                positive_expected_result_path, name, severity, dry_run
            )

            if metadata_updated or positive_updated:
                updated += 1

        except Exception as e:
            print(f"Error processing {md_file}: {e}", file=sys.stderr)
            errors += 1

    return processed, updated, errors


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Sync markdown documentation changes to metadata.json files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync all markdown files in documentation/rules/
  python sync_md_to_metadata.py

  # Sync specific files
  python sync_md_to_metadata.py -f documentation/rules/terraform/gcp/stackdriver_logging_disabled.md

  # Dry run to see what would change
  python sync_md_to_metadata.py --dry-run

  # Verbose output for debugging
  python sync_md_to_metadata.py -v

  # Custom directories (useful for GitHub Actions)
  python sync_md_to_metadata.py --md-dir ./documentation/rules --assets-dir ./assets/queries
        """,
    )

    parser.add_argument(
        "--md-dir",
        type=Path,
        default=Path("documentation/rules"),
        help="Path to documentation/rules directory (default: documentation/rules)",
    )

    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=Path("assets/queries"),
        help="Path to assets/queries directory (default: assets/queries)",
    )

    parser.add_argument(
        "-f",
        "--files",
        nargs="+",
        help="Specific markdown files to process (space-separated)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without making changes",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed processing information",
    )

    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit with non-zero code if no files were updated",
    )

    args = parser.parse_args()

    # Validate directories
    if not args.md_dir.exists():
        print(
            f"Error: Documentation directory not found: {args.md_dir}", file=sys.stderr
        )
        sys.exit(1)

    if not args.assets_dir.exists():
        print(
            f"Error: Assets/queries directory not found: {args.assets_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Run sync
    print(f"Syncing markdown files from {args.md_dir} to {args.assets_dir}")
    if args.dry_run:
        print("[DRY RUN MODE - No changes will be made]")

    processed, updated, errors = sync_md_to_metadata(
        args.md_dir, args.assets_dir, args.files, args.dry_run, args.verbose
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Summary:")
    print(f"  Processed: {processed} files")
    print(f"  Updated:   {updated} files")
    print(f"  Errors:    {errors} files")
    print(f"{'='*60}")

    # Exit codes
    if errors > 0:
        sys.exit(1)

    if args.ci and updated == 0:
        print("\nCI mode: No files were updated")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
