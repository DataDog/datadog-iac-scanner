#!/usr/bin/env python3
"""
Terraform JSON Plan Generator

This script recursively finds .tf files and generates corresponding JSON plan files.
It uses AI-powered auto-fixing to handle terraform init failures.
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from anthropic import Anthropic
except ImportError:
    print("Error: anthropic package not installed. Run: pip install anthropic")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class TerraformPlanGenerator:
    """Handles Terraform plan generation with AI-powered error fixing."""

    def __init__(
        self,
        max_retries: int = 3,
        anthropic_api_key: Optional[str] = None,
        verbose: bool = False
    ):
        """
        Initialize the generator.

        Args:
            max_retries: Maximum number of retry attempts for terraform init
            anthropic_api_key: API key for Claude (defaults to ANTHROPIC_API_KEY env var)
            verbose: Enable verbose logging
        """
        self.max_retries = max_retries
        self.verbose = verbose

        if verbose:
            logger.setLevel(logging.DEBUG)

        # Initialize Claude client
        api_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable "
                "or pass it via --api-key argument."
            )

        # Use standard Anthropic API, not internal gateways
        # Parse custom headers if present
        custom_headers = {}
        custom_headers_str = os.environ.get("ANTHROPIC_CUSTOM_HEADERS", "")
        if custom_headers_str:
            for line in custom_headers_str.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    custom_headers[key.strip()] = value.strip()

        # Initialize client with standard API endpoint
        client_kwargs = {
            "api_key": api_key,
            "base_url": "https://api.anthropic.com",
        }
        if custom_headers:
            client_kwargs["default_headers"] = custom_headers

        self.client = Anthropic(**client_kwargs)

        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'skipped': 0
        }

    def find_tf_files(self, root_dir: Path) -> List[Path]:
        """
        Recursively find all .tf files in the given directory.

        Args:
            root_dir: Root directory to search

        Returns:
            List of Path objects for .tf files
        """
        logger.info(f"Searching for .tf files in {root_dir}")
        tf_files = list(root_dir.rglob("*.tf"))
        logger.info(f"Found {len(tf_files)} .tf files")
        return tf_files

    def run_command(
        self,
        cmd: List[str],
        cwd: Path,
        timeout: int = 300
    ) -> Tuple[bool, str, str]:
        """
        Run a shell command and return success status and output.

        Args:
            cmd: Command and arguments as a list
            cwd: Working directory
            timeout: Command timeout in seconds

        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            logger.debug(f"Running command: {' '.join(cmd)} in {cwd}")

            # Create clean environment for terraform (remove problematic variables)
            env = os.environ.copy()
            # Remove OTEL_TRACES_EXPORTER to avoid terraform telemetry errors
            env.pop('OTEL_TRACES_EXPORTER', None)
            env.pop('OTEL_EXPORTER_OTLP_PROTOCOL', None)

            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            success = result.returncode == 0
            return success, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", str(e)

    def fix_terraform_with_ai(
        self,
        tf_content: str,
        error_message: str,
        attempt: int
    ) -> Optional[str]:
        """
        Use Claude to fix Terraform configuration errors.

        Args:
            tf_content: Original Terraform file content
            error_message: Error message from terraform init
            attempt: Current retry attempt number

        Returns:
            Fixed Terraform content or None if fixing failed
        """
        logger.info(f"Attempting AI fix (attempt {attempt}/{self.max_retries})")

        if "terraform plan" in error_message.lower() or "terraform plan error" in error_message.lower():
            # Plan-specific errors often need mock providers and stub resources
            prompt = f"""You are a Terraform expert fixing a terraform plan error. The error is:

ERROR:
{error_message}

CURRENT TERRAFORM FILE:
{tf_content}

Fix this error by:
1. Adding a mock AWS provider if missing (use skip_credentials_validation and skip_requesting_account_id):
   terraform {{
     required_providers {{
       aws = {{
         source = "hashicorp/aws"
         version = "~> 5.0"
       }}
     }}
   }}
   provider "aws" {{
     region = "us-east-1"
     skip_credentials_validation = true
     skip_requesting_account_id = true
     skip_metadata_api_check = true
     access_key = "mock_access_key"
     secret_key = "mock_secret_key"
   }}

2. Add stub/mock resources for any referenced but undefined resources
3. Fix any syntax errors to match Terraform 1.0.x syntax (NOT 1.15.x)

Return ONLY the corrected Terraform code without explanations or markdown."""
        else:
            # Init-specific errors
            prompt = f"""You are a Terraform expert. A terraform init command failed with the following error:

ERROR:
{error_message}

TERRAFORM FILE CONTENT:
{tf_content}

Please fix the Terraform configuration to resolve this error. Return ONLY the corrected Terraform code without any explanations or markdown formatting.
The output should be valid .tf file content that can be directly saved and used."""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}]
            )

            fixed_content = message.content[0].text.strip()

            # Remove markdown code blocks if present
            if fixed_content.startswith("```"):
                lines = fixed_content.split("\n")
                # Remove first line (```terraform or ```hcl or ```)
                lines = lines[1:]
                # Remove last line (```)
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                fixed_content = "\n".join(lines)

            logger.debug(f"AI suggested fix:\n{fixed_content[:200]}...")
            return fixed_content
        except Exception as e:
            logger.error(f"AI fixing failed: {e}")
            return None

    def process_tf_file(
        self,
        tf_file: Path,
        skip_existing: bool = False
    ) -> bool:
        """
        Process a single .tf file to generate its JSON plan.

        Args:
            tf_file: Path to the .tf file
            skip_existing: Skip if JSON file already exists

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Processing {tf_file}")

        # Check if JSON already exists
        json_file = tf_file.with_suffix('.json')
        if skip_existing and json_file.exists():
            logger.info(f"Skipping {tf_file} (JSON already exists)")
            self.stats['skipped'] += 1
            return True

        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            temp_tf = temp_path / tf_file.name

            # Copy .tf file to temp directory
            shutil.copy2(tf_file, temp_tf)
            logger.debug(f"Copied {tf_file} to {temp_tf}")

            # Read original content
            with open(temp_tf, 'r') as f:
                original_content = f.read()

            current_content = original_content

            # Try terraform init with retries
            for attempt in range(1, self.max_retries + 1):
                logger.debug(f"Terraform init attempt {attempt}/{self.max_retries}")

                # Run terraform init
                success, stdout, stderr = self.run_command(
                    ["terraform", "init"],
                    temp_path
                )

                if success:
                    logger.debug("Terraform init successful")
                    break

                logger.warning(f"Terraform init failed (attempt {attempt}): {stderr[:200]}")

                if attempt < self.max_retries:
                    # Try to fix with AI
                    fixed_content = self.fix_terraform_with_ai(
                        current_content,
                        stderr,
                        attempt
                    )

                    if fixed_content:
                        # Write fixed content
                        with open(temp_tf, 'w') as f:
                            f.write(fixed_content)
                        current_content = fixed_content
                        logger.info("Applied AI fix, retrying...")
                    else:
                        logger.error("AI fix failed")
                        return False
                else:
                    logger.error(f"Failed to initialize {tf_file} after {self.max_retries} attempts")
                    return False

            # If we modified the content during init fixes, save it
            init_modified_content = current_content != original_content

            # Try terraform plan with retries
            for plan_attempt in range(1, self.max_retries + 1):
                logger.debug(f"Terraform plan attempt {plan_attempt}/{self.max_retries}")

                # Run terraform plan
                success, stdout, stderr = self.run_command(
                    ["terraform", "plan", "-out=tfplan"],
                    temp_path
                )

                if success:
                    logger.debug("Terraform plan successful")
                    break

                logger.warning(f"Terraform plan failed (attempt {plan_attempt}): {stderr[:200]}")

                if plan_attempt < self.max_retries:
                    # Try to fix plan errors with AI
                    fixed_content = self.fix_terraform_with_ai(
                        current_content,
                        f"Terraform plan error:\n{stderr}",
                        plan_attempt
                    )

                    if fixed_content:
                        # Write fixed content
                        with open(temp_tf, 'w') as f:
                            f.write(fixed_content)
                        current_content = fixed_content
                        logger.info("Applied AI fix for plan error, retrying...")

                        # Re-run init if content changed significantly
                        reinit_success, _, _ = self.run_command(
                            ["terraform", "init", "-upgrade"],
                            temp_path
                        )
                        if not reinit_success:
                            logger.warning("Re-init after plan fix failed, continuing anyway...")
                    else:
                        logger.error("AI fix for plan error failed")
                        return False
                else:
                    logger.error(f"Failed to generate plan for {tf_file} after {self.max_retries} attempts")
                    return False

            # If we modified the content (during init or plan fixes), update the original file
            if current_content != original_content:
                logger.info(f"Updating {tf_file} with AI-fixed version")
                with open(tf_file, 'w') as f:
                    f.write(current_content)

            # Convert plan to JSON
            logger.debug("Converting plan to JSON")
            success, stdout, stderr = self.run_command(
                ["terraform", "show", "-json", "tfplan"],
                temp_path
            )

            if not success:
                logger.error(f"Terraform show failed: {stderr[:200]}")
                return False

            # Validate JSON output
            try:
                json_data = json.loads(stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON output: {e}")
                return False

            # Write JSON to original directory
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=2)

            logger.info(f"✓ Successfully generated {json_file}")
            return True

    def process_directory(
        self,
        root_dir: Path,
        skip_existing: bool = False,
        workers: int = 1
    ) -> Dict[str, int]:
        """
        Process all .tf files in a directory.

        Args:
            root_dir: Root directory containing .tf files
            skip_existing: Skip files with existing JSON plans
            workers: Number of concurrent workers

        Returns:
            Statistics dictionary
        """
        tf_files = self.find_tf_files(root_dir)
        self.stats['total'] = len(tf_files)

        if not tf_files:
            logger.warning("No .tf files found")
            return self.stats

        if workers == 1:
            # Sequential processing
            for tf_file in tf_files:
                if self.process_tf_file(tf_file, skip_existing):
                    self.stats['success'] += 1
                else:
                    self.stats['failed'] += 1
        else:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self.process_tf_file, tf_file, skip_existing): tf_file
                    for tf_file in tf_files
                }

                for future in as_completed(futures):
                    tf_file = futures[future]
                    try:
                        if future.result():
                            self.stats['success'] += 1
                        else:
                            self.stats['failed'] += 1
                    except Exception as e:
                        logger.error(f"Error processing {tf_file}: {e}")
                        self.stats['failed'] += 1

        return self.stats

    def print_summary(self):
        """Print processing summary."""
        print("\n" + "=" * 60)
        print("PROCESSING SUMMARY")
        print("=" * 60)
        print(f"Total files:      {self.stats['total']}")
        print(f"✓ Success:        {self.stats['success']}")
        print(f"✗ Failed:         {self.stats['failed']}")
        print(f"⊘ Skipped:        {self.stats['skipped']}")
        print("=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate JSON plan files for Terraform configurations with AI-powered error fixing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all .tf files in current directory
  python generate_tf_plans.py .

  # Process with 4 concurrent workers
  python generate_tf_plans.py /path/to/terraform --workers 4

  # Skip files that already have JSON plans
  python generate_tf_plans.py /path/to/terraform --skip-existing

  # Verbose output with custom retry limit
  python generate_tf_plans.py /path/to/terraform --verbose --max-retries 5
        """
    )

    parser.add_argument(
        "directory",
        type=Path,
        help="Root directory containing .tf files"
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts for terraform init (default: 3)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of concurrent workers for parallel processing (default: 1)"
    )

    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip .tf files that already have corresponding .json files"
    )

    parser.add_argument(
        "--api-key",
        type=str,
        help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var)"
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without making changes"
    )

    args = parser.parse_args()

    # Validate directory
    if not args.directory.exists():
        print(f"Error: Directory {args.directory} does not exist")
        sys.exit(1)

    if not args.directory.is_dir():
        print(f"Error: {args.directory} is not a directory")
        sys.exit(1)

    # Dry run mode
    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
        generator = TerraformPlanGenerator(
            max_retries=args.max_retries,
            anthropic_api_key=args.api_key,
            verbose=args.verbose
        )
        tf_files = generator.find_tf_files(args.directory)
        print(f"\nWould process {len(tf_files)} .tf files:")
        for tf_file in tf_files:
            json_file = tf_file.with_suffix('.json')
            status = "EXISTS" if json_file.exists() else "NEW"
            skip_marker = " (would skip)" if args.skip_existing and json_file.exists() else ""
            print(f"  [{status}] {tf_file}{skip_marker}")
        sys.exit(0)

    # Create generator and process files
    try:
        generator = TerraformPlanGenerator(
            max_retries=args.max_retries,
            anthropic_api_key=args.api_key,
            verbose=args.verbose
        )

        generator.process_directory(
            args.directory,
            skip_existing=args.skip_existing,
            workers=args.workers
        )

        generator.print_summary()

        # Exit with error code if any files failed
        if generator.stats['failed'] > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
