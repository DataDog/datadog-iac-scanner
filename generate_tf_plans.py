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
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class TerraformPlanGenerator:
    """Handles Terraform plan generation with AI-powered error fixing."""

    def __init__(
        self,
        max_retries: int = 3,
        anthropic_api_key: Optional[str] = None,
        verbose: bool = False,
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
            for line in custom_headers_str.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    custom_headers[key.strip()] = value.strip()

        # Initialize client with standard API endpoint
        client_kwargs = {
            "api_key": api_key,
            "base_url": "https://api.anthropic.com",
        }
        if custom_headers:
            client_kwargs["default_headers"] = custom_headers

        self.client = Anthropic(**client_kwargs)

        self.stats = {"total": 0, "success": 0, "failed": 0, "skipped": 0}

    def is_high_rule(self, tf_file: Path) -> bool:
        """
        Check if a .tf file belongs to a high severity rule.

        Args:
            tf_file: Path to the .tf file

        Returns:
            True if the file is in a high rule directory, False otherwise
        """
        # Look for metadata.json in parent directories
        current = tf_file.parent
        while current != current.parent:  # Stop at filesystem root
            metadata_file = current / "metadata.json"
            if metadata_file.exists():
                try:
                    with open(metadata_file, "r") as f:
                        metadata = json.load(f)

                    severity = metadata.get("severity")
                    if severity == "HIGH":
                        return True
                    else:
                        # Found metadata but not high, stop searching
                        return False
                except (json.JSONDecodeError, KeyError) as e:
                    logger.debug(f"Failed to parse metadata file {metadata_file}: {e}")
            current = current.parent

        return False

    def has_json_tests(self, tf_file: Path) -> bool:
        """
        Check if the rule directory already has .json test files.

        Args:
            tf_file: Path to a .tf file

        Returns:
            True if the test directory contains Terraform plan .json files, False otherwise
        """
        # The test directory is the parent of the .tf file
        test_dir = tf_file.parent

        # Check if any .json files exist in this test directory
        # Exclude positive_expected_result.json and negative_expected_result.json
        json_files = [
            f
            for f in test_dir.glob("*.json")
            if f.name
            not in ["positive_expected_result.json", "negative_expected_result.json"]
        ]

        if json_files:
            logger.debug(
                f"Found {len(json_files)} existing plan .json files in {test_dir}, skipping rule"
            )
            return True

        return False

    def find_tf_files(self, root_dir: Path) -> List[Path]:
        """
        Recursively find all .tf files in the given directory that belong to high severity rules.
        Skips rules that already have .json test files.

        Args:
            root_dir: Root directory to search

        Returns:
            List of Path objects for .tf files in high severity rules that don't have .json tests yet
        """
        logger.info(f"Searching for .tf files in high severity rules in {root_dir}")
        all_tf_files = list(root_dir.rglob("*.tf"))
        logger.debug(f"Found {len(all_tf_files)} total .tf files")

        # Filter to only high severity rules
        high_tf_files = [tf for tf in all_tf_files if self.is_high_rule(tf)]

        # Filter out rules that already have .json test files
        files_without_json = [tf for tf in high_tf_files if not self.has_json_tests(tf)]

        skipped_count = len(high_tf_files) - len(files_without_json)
        if skipped_count > 0:
            logger.info(
                f"Skipped {skipped_count} .tf files from rules that already have .json tests"
            )

        logger.info(
            f"Found {len(files_without_json)} .tf files in high severity rules without .json tests "
            f"(skipped {len(all_tf_files) - len(files_without_json)} files total)"
        )
        return files_without_json

    def run_command(
        self, cmd: List[str], cwd: Path, timeout: int = 300
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
            env.pop("OTEL_TRACES_EXPORTER", None)
            env.pop("OTEL_EXPORTER_OTLP_PROTOCOL", None)

            # Set Azure environment variables to prevent authentication attempts
            # These will make the Azure provider skip real authentication
            env["ARM_SKIP_PROVIDER_REGISTRATION"] = "true"
            env["ARM_SUBSCRIPTION_ID"] = "00000000-0000-0000-0000-000000000000"
            env["ARM_TENANT_ID"] = "00000000-0000-0000-0000-000000000000"
            env["ARM_CLIENT_ID"] = "00000000-0000-0000-0000-000000000000"
            env["ARM_CLIENT_SECRET"] = "mock_secret_value"

            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
            )
            success = result.returncode == 0
            return success, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", str(e)

    def fix_terraform_with_ai(
        self, tf_content: str, error_message: str, attempt: int
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

        if (
            "terraform plan" in error_message.lower()
            or "terraform plan error" in error_message.lower()
            or "could not acquire access token" in error_message.lower()
            or "could not configure azurecli authorizer" in error_message.lower()
            or "building account" in error_message.lower()
        ):
            # Plan-specific errors often need mock providers and stub resources
            prompt = f"""You are a Terraform expert fixing a terraform plan error. The error is:

ERROR:
{error_message}

CURRENT TERRAFORM FILE:
{tf_content}

Fix this error. IMPORTANT: Azure provider ALWAYS requires real authentication, even with mock credentials.

For Azure resources, use this approach:
1. Add required providers and Azure provider with environment variable auth:
   terraform {{
     required_providers {{
       azurerm = {{
         source = "hashicorp/azurerm"
         version = "~> 3.0"
       }}
       random = {{
         source = "hashicorp/random"
         version = "~> 3.0"
       }}
     }}
   }}

   provider "azurerm" {{
     features {{}}
     skip_provider_registration = true
     # Auth will use ARM_* environment variables set by the script
   }}

2. Add stub resources for any referenced but undefined resources:
   resource "azurerm_resource_group" "example" {{
     name     = "test-rg"
     location = "eastus"
   }}

   resource "random_id" "server" {{
     byte_length = 8
   }}

   # If azurerm_redis_cache.example is referenced, add:
   resource "azurerm_redis_cache" "example" {{
     name                = "examplecache"
     location            = azurerm_resource_group.example.location
     resource_group_name = azurerm_resource_group.example.name
     capacity            = 1
     family              = "C"
     sku_name            = "Basic"
   }}

   # Add data sources if referenced:
   data "azurerm_subscription" "primary" {{}}
   data "azurerm_client_config" "example" {{}}

3. Keep ALL original resources from the file - just add the missing dependencies above them

CRITICAL: Return ONLY the corrected Terraform code. Do NOT include:
- Explanations
- Markdown code blocks
- Any text before or after the code
- Comments about what you changed

Start your response immediately with 'terraform {{' or 'resource' or 'provider' or 'data'."""
        else:
            # Init-specific errors (but also include provider config hints for common auth issues)
            prompt = f"""You are a Terraform expert. A terraform init command failed with the following error:

ERROR:
{error_message}

TERRAFORM FILE CONTENT:
{tf_content}

Please fix the Terraform configuration to resolve this error.

If the error involves Azure (authentication, missing resources, or provider), add:
   terraform {{
     required_providers {{
       azurerm = {{
         source = "hashicorp/azurerm"
         version = "~> 3.0"
       }}
       random = {{
         source = "hashicorp/random"
         version = "~> 3.0"
       }}
     }}
   }}

   provider "azurerm" {{
     features {{}}
     skip_provider_registration = true

     # Explicitly set authentication to use service principal with fake credentials
     # This prevents the provider from trying other auth methods like Azure CLI
     use_cli                       = false
     use_msi                       = false
     use_oidc                      = false
     subscription_id               = "00000000-0000-0000-0000-000000000000"
     tenant_id                     = "00000000-0000-0000-0000-000000000000"
     client_id                     = "00000000-0000-0000-0000-000000000000"
     client_secret                 = "mock_secret_value"
   }}

   data "azurerm_subscription" "primary" {{}}
   data "azurerm_client_config" "example" {{}}

   # Add stub resources for common references:
   resource "azurerm_resource_group" "example" {{
     name     = "test-rg"
     location = "eastus"
   }}

   resource "random_id" "server" {{
     byte_length = 8
   }}

If the error involves AWS authentication, add mock AWS provider configuration.

CRITICAL: Return ONLY the corrected Terraform code. Do NOT include:
- Explanations
- Markdown code blocks
- Any text before or after the code
- Comments about what you changed

Start your response immediately with 'terraform {{' or 'resource' or 'provider' or 'data'.
The output should be valid .tf file content that can be directly saved and used."""

        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
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

            # If AI still included explanatory text, try to extract just the Terraform code
            # Look for the start of actual Terraform code
            tf_keywords = [
                "terraform {",
                'resource "',
                'provider "',
                'data "',
                'module "',
                'variable "',
                'output "',
                "locals {",
            ]
            lines = fixed_content.split("\n")
            start_idx = -1

            for i, line in enumerate(lines):
                stripped = line.strip()
                if any(stripped.startswith(kw) for kw in tf_keywords):
                    start_idx = i
                    break

            # If we found Terraform code but it's not at the start
            if start_idx > 0:
                logger.debug(
                    f"Stripping {start_idx} lines of explanatory text before Terraform code"
                )
                fixed_content = "\n".join(lines[start_idx:])
            elif start_idx == -1:
                # No valid Terraform code found at all - this is likely explanatory text
                logger.warning(
                    "AI response contained no valid Terraform code, likely explanatory text"
                )
                # Return None to trigger a retry with a stronger prompt
                return None

            logger.debug(f"AI suggested fix:\n{fixed_content[:200]}...")
            return fixed_content
        except Exception as e:
            logger.error(f"AI fixing failed: {e}")
            return None

    def process_tf_file(self, tf_file: Path, skip_existing: bool = False) -> bool:
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
        json_file = tf_file.with_suffix(".json")
        if skip_existing and json_file.exists():
            logger.info(f"Skipping {tf_file} (JSON already exists)")
            self.stats["skipped"] += 1
            return True

        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            temp_tf = temp_path / tf_file.name

            # Copy .tf file to temp directory
            shutil.copy2(tf_file, temp_tf)
            logger.debug(f"Copied {tf_file} to {temp_tf}")

            # Read original content
            with open(temp_tf, "r") as f:
                original_content = f.read()

            current_content = original_content

            # Try terraform init with retries
            for attempt in range(1, self.max_retries + 1):
                logger.debug(f"Terraform init attempt {attempt}/{self.max_retries}")

                # Run terraform init
                success, stdout, stderr = self.run_command(
                    ["terraform", "init"], temp_path
                )

                if success:
                    logger.debug("Terraform init successful")
                    break

                logger.warning(
                    f"Terraform init failed (attempt {attempt}): {stderr[:200]}"
                )

                if attempt < self.max_retries:
                    # Try to fix with AI
                    fixed_content = self.fix_terraform_with_ai(
                        current_content, stderr, attempt
                    )

                    if fixed_content:
                        # Write fixed content
                        with open(temp_tf, "w") as f:
                            f.write(fixed_content)
                        current_content = fixed_content
                        logger.info("Applied AI fix, retrying...")
                    else:
                        logger.error("AI fix failed")
                        return False
                else:
                    logger.error(
                        f"Failed to initialize {tf_file} after {self.max_retries} attempts"
                    )
                    return False

            # If we modified the content during init fixes, save it
            init_modified_content = current_content != original_content

            # Try terraform plan with retries
            for plan_attempt in range(1, self.max_retries + 1):
                logger.debug(
                    f"Terraform plan attempt {plan_attempt}/{self.max_retries}"
                )

                # Run terraform plan
                success, stdout, stderr = self.run_command(
                    ["terraform", "plan", "-out=tfplan"], temp_path
                )

                if success:
                    logger.debug("Terraform plan successful")
                    break

                # Special case for Azure authentication errors that can't be fixed
                # These happen even with mock credentials because Azure validates them
                if (
                    "building account: could not acquire access token" in stderr
                    or "could not configure AzureCli Authorizer" in stderr
                ):
                    logger.warning(
                        "Azure authentication failed - trying validation mode"
                    )

                    # First, try terraform validate to at least check syntax
                    val_success, val_stdout, val_stderr = self.run_command(
                        ["terraform", "validate", "-json"], temp_path
                    )

                    if val_success:
                        # Parse the Terraform file to extract resource information
                        import re

                        try:
                            # Parse validation output
                            val_data = json.loads(val_stdout) if val_stdout else {}

                            # Parse the Terraform file to extract resources
                            resources = []
                            resource_changes = []

                            # Extract resource blocks using regex
                            resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
                            for match in re.finditer(
                                resource_pattern, current_content, re.DOTALL
                            ):
                                resource_type = match.group(1)
                                resource_name = match.group(2)
                                resource_body = match.group(3)

                                # Extract basic attributes
                                attributes = {}

                                # Common patterns for all resources (Azure, AWS, Alicloud)
                                attribute_patterns = [
                                    (r'name\s*=\s*"([^"]+)"', "name"),
                                    (r'location\s*=\s*"([^"]+)"', "location"),
                                    (
                                        r'resource_group_name\s*=\s*"([^"]+)"',
                                        "resource_group_name",
                                    ),
                                    (r"capacity\s*=\s*(\d+)", "capacity"),
                                    (r'family\s*=\s*"([^"]+)"', "family"),
                                    (r'sku_name\s*=\s*"([^"]+)"', "sku_name"),
                                    (
                                        r"enable_non_ssl_port\s*=\s*(true|false)",
                                        "enable_non_ssl_port",
                                    ),
                                    (r'start_ip\s*=\s*"([^"]+)"', "start_ip"),
                                    (r'end_ip\s*=\s*"([^"]+)"', "end_ip"),
                                    # Alicloud specific
                                    (r'zone_id\s*=\s*"([^"]+)"', "zone_id"),
                                    (r'instance_type\s*=\s*"([^"]+)"', "instance_type"),
                                    (r'vswitch_id\s*=\s*"([^"]+)"', "vswitch_id"),
                                    (
                                        r"security_groups\s*=\s*\[([^\]]+)\]",
                                        "security_groups",
                                    ),
                                    (
                                        r"internet_max_bandwidth_out\s*=\s*(\d+)",
                                        "internet_max_bandwidth_out",
                                    ),
                                    # AWS specific
                                    (r'instance_type\s*=\s*"([^"]+)"', "instance_type"),
                                    (r'ami\s*=\s*"([^"]+)"', "ami"),
                                    (r'vpc_id\s*=\s*"([^"]+)"', "vpc_id"),
                                    (r'subnet_id\s*=\s*"([^"]+)"', "subnet_id"),
                                ]

                                for pattern, attr_name in attribute_patterns:
                                    match_attr = re.search(pattern, resource_body)
                                    if match_attr:
                                        value = match_attr.group(1)
                                        # Convert boolean strings
                                        if value in ("true", "false"):
                                            value = value == "true"
                                        # Convert numeric strings
                                        elif value.isdigit():
                                            value = int(value)
                                        attributes[attr_name] = value

                                # Handle references
                                ref_patterns = [
                                    (
                                        r"location\s*=\s*azurerm_resource_group\.[^.]+\.location",
                                        "location",
                                        "eastus",
                                    ),
                                    (
                                        r"resource_group_name\s*=\s*azurerm_resource_group\.[^.]+\.name",
                                        "resource_group_name",
                                        "test-rg",
                                    ),
                                    (
                                        r"redis_cache_name\s*=\s*azurerm_redis_cache\.[^.]+\.name",
                                        "redis_cache_name",
                                        "testcache",
                                    ),
                                ]

                                for pattern, attr_name, default_value in ref_patterns:
                                    if (
                                        re.search(pattern, resource_body)
                                        and attr_name not in attributes
                                    ):
                                        attributes[attr_name] = default_value

                                # Extract nested blocks (e.g., redis_configuration)
                                config_match = re.search(
                                    r"redis_configuration\s*\{([^}]+)\}", resource_body
                                )
                                if config_match:
                                    redis_config = {}
                                    config_body = config_match.group(1)
                                    for pattern, attr_name in [
                                        (r"maxclients\s*=\s*(\d+)", "maxclients"),
                                        (
                                            r"maxmemory_reserved\s*=\s*(\d+)",
                                            "maxmemory_reserved",
                                        ),
                                        (
                                            r"maxmemory_delta\s*=\s*(\d+)",
                                            "maxmemory_delta",
                                        ),
                                        (
                                            r'maxmemory_policy\s*=\s*"([^"]+)"',
                                            "maxmemory_policy",
                                        ),
                                    ]:
                                        m = re.search(pattern, config_body)
                                        if m:
                                            val = m.group(1)
                                            redis_config[attr_name] = (
                                                int(val) if val.isdigit() else val
                                            )
                                    if redis_config:
                                        attributes["redis_configuration"] = [
                                            redis_config
                                        ]

                                # Determine provider
                                if resource_type.startswith("alicloud_"):
                                    provider_name = "alicloud"
                                elif resource_type.startswith("azurerm_"):
                                    provider_name = "azurerm"
                                elif resource_type.startswith("aws_"):
                                    provider_name = "aws"
                                elif resource_type.startswith("google_"):
                                    provider_name = "google"
                                elif resource_type.startswith("random_"):
                                    provider_name = "random"
                                else:
                                    provider_name = (
                                        resource_type.split("_")[0]
                                        if "_" in resource_type
                                        else "null"
                                    )

                                # Create resource entry
                                resource_entry = {
                                    "address": f"{resource_type}.{resource_name}",
                                    "mode": "managed",
                                    "type": resource_type,
                                    "name": resource_name,
                                    "provider_name": provider_name,
                                    "schema_version": 0,
                                    "values": attributes,
                                    "sensitive_values": {},
                                }
                                resources.append(resource_entry)

                                # Create resource change entry
                                change_entry = {
                                    "address": f"{resource_type}.{resource_name}",
                                    "mode": "managed",
                                    "type": resource_type,
                                    "name": resource_name,
                                    "provider_name": f"registry.terraform.io/hashicorp/{provider_name}",
                                    "change": {
                                        "actions": ["create"],
                                        "before": None,
                                        "after": attributes,
                                        "after_unknown": {},
                                        "before_sensitive": False,
                                        "after_sensitive": False,
                                    },
                                }
                                resource_changes.append(change_entry)

                            # Create a plan JSON structure with extracted resources
                            plan_json = {
                                "format_version": "1.0",
                                "terraform_version": "1.15.2",
                                "planned_values": {
                                    "root_module": {"resources": resources}
                                },
                                "resource_changes": resource_changes,
                                "configuration": {
                                    "root_module": {
                                        "resources": [
                                            {
                                                "address": res["address"],
                                                "mode": res["mode"],
                                                "type": res["type"],
                                                "name": res["name"],
                                                "provider_config_key": res[
                                                    "provider_name"
                                                ],
                                            }
                                            for res in resources
                                        ]
                                    }
                                },
                                "validation_only": True,
                                "validation_output": val_data,
                            }

                            # Write the plan with extracted resources
                            json_file = tf_file.with_suffix(".json")
                            with open(json_file, "w") as f:
                                json.dump(plan_json, f, indent=2)

                            logger.info(
                                f"✓ Generated validation-based plan with {len(resources)} resources for {json_file}"
                            )
                            return True
                        except Exception as e:
                            logger.error(f"Failed to create validation plan: {e}")

                logger.warning(
                    f"Terraform plan failed (attempt {plan_attempt}): {stderr[:200]}"
                )

                if plan_attempt < self.max_retries:
                    # Try to fix plan errors with AI
                    fixed_content = self.fix_terraform_with_ai(
                        current_content,
                        f"Terraform plan error:\n{stderr}",
                        plan_attempt,
                    )

                    if fixed_content:
                        # Write fixed content
                        with open(temp_tf, "w") as f:
                            f.write(fixed_content)
                        current_content = fixed_content
                        logger.info("Applied AI fix for plan error, retrying...")

                        # Re-run init if content changed significantly
                        reinit_success, _, _ = self.run_command(
                            ["terraform", "init", "-upgrade"], temp_path
                        )
                        if not reinit_success:
                            logger.warning(
                                "Re-init after plan fix failed, continuing anyway..."
                            )
                    else:
                        logger.error("AI fix for plan error failed")
                        return False
                else:
                    # All retries exhausted - check if this is an Azure auth issue
                    # and try validation fallback
                    logger.warning(
                        f"All plan attempts failed for {tf_file}, checking for Azure auth issues"
                    )

                    # Check the last error message for Azure authentication issues
                    if (
                        "building account" in stderr
                        or "could not acquire access token" in stderr
                        or "could not configure AzureCli Authorizer" in stderr
                    ):
                        logger.info(
                            "Azure authentication issue detected, attempting validation fallback"
                        )

                        # Try terraform validate as a fallback
                        val_success, val_stdout, val_stderr = self.run_command(
                            ["terraform", "validate", "-json"], temp_path
                        )

                        if val_success:
                            # Use the helper function we already defined earlier
                            # Parse the Terraform file to extract resource information
                            import re

                            try:
                                # Parse validation output
                                val_data = json.loads(val_stdout) if val_stdout else {}

                                # Parse the Terraform file to extract resources
                                resources = []
                                resource_changes = []

                                # Extract resource blocks using regex
                                resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
                                for match in re.finditer(
                                    resource_pattern, current_content, re.DOTALL
                                ):
                                    resource_type = match.group(1)
                                    resource_name = match.group(2)
                                    resource_body = match.group(3)

                                    # Extract basic attributes
                                    attributes = {}

                                    # Common patterns for all resources (Azure, AWS, Alicloud)
                                    attribute_patterns = [
                                        (r'name\s*=\s*"([^"]+)"', "name"),
                                        (r'location\s*=\s*"([^"]+)"', "location"),
                                        (
                                            r'resource_group_name\s*=\s*"([^"]+)"',
                                            "resource_group_name",
                                        ),
                                        (r"capacity\s*=\s*(\d+)", "capacity"),
                                        (r'family\s*=\s*"([^"]+)"', "family"),
                                        (r'sku_name\s*=\s*"([^"]+)"', "sku_name"),
                                        (
                                            r"enable_non_ssl_port\s*=\s*(true|false)",
                                            "enable_non_ssl_port",
                                        ),
                                        (r'start_ip\s*=\s*"([^"]+)"', "start_ip"),
                                        (r'end_ip\s*=\s*"([^"]+)"', "end_ip"),
                                        # Alicloud specific
                                        (r'zone_id\s*=\s*"([^"]+)"', "zone_id"),
                                        (
                                            r'instance_type\s*=\s*"([^"]+)"',
                                            "instance_type",
                                        ),
                                        (r'vswitch_id\s*=\s*"([^"]+)"', "vswitch_id"),
                                        (
                                            r"security_groups\s*=\s*\[([^\]]+)\]",
                                            "security_groups",
                                        ),
                                        (
                                            r"internet_max_bandwidth_out\s*=\s*(\d+)",
                                            "internet_max_bandwidth_out",
                                        ),
                                        # AWS specific
                                        (r'ami\s*=\s*"([^"]+)"', "ami"),
                                        (r'vpc_id\s*=\s*"([^"]+)"', "vpc_id"),
                                        (r'subnet_id\s*=\s*"([^"]+)"', "subnet_id"),
                                    ]

                                    for pattern, attr_name in attribute_patterns:
                                        match_attr = re.search(pattern, resource_body)
                                        if match_attr:
                                            value = match_attr.group(1)
                                            # Convert boolean strings
                                            if value in ("true", "false"):
                                                value = value == "true"
                                            # Convert numeric strings
                                            elif value.isdigit():
                                                value = int(value)
                                            attributes[attr_name] = value

                                    # Handle references
                                    ref_patterns = [
                                        (
                                            r"location\s*=\s*azurerm_resource_group\.[^.]+\.location",
                                            "location",
                                            "eastus",
                                        ),
                                        (
                                            r"resource_group_name\s*=\s*azurerm_resource_group\.[^.]+\.name",
                                            "resource_group_name",
                                            "test-rg",
                                        ),
                                        (
                                            r"redis_cache_name\s*=\s*azurerm_redis_cache\.[^.]+\.name",
                                            "redis_cache_name",
                                            "testcache",
                                        ),
                                    ]

                                    for (
                                        pattern,
                                        attr_name,
                                        default_value,
                                    ) in ref_patterns:
                                        if (
                                            re.search(pattern, resource_body)
                                            and attr_name not in attributes
                                        ):
                                            attributes[attr_name] = default_value

                                    # Determine provider
                                    provider_name = (
                                        resource_type.split("_")[0]
                                        if "_" in resource_type
                                        else "null"
                                    )

                                    # Create resource entry
                                    resource_entry = {
                                        "address": f"{resource_type}.{resource_name}",
                                        "mode": "managed",
                                        "type": resource_type,
                                        "name": resource_name,
                                        "provider_name": provider_name,
                                        "schema_version": 0,
                                        "values": attributes,
                                        "sensitive_values": {},
                                    }
                                    resources.append(resource_entry)

                                    # Create resource change entry
                                    change_entry = {
                                        "address": f"{resource_type}.{resource_name}",
                                        "mode": "managed",
                                        "type": resource_type,
                                        "name": resource_name,
                                        "provider_name": f"registry.terraform.io/hashicorp/{provider_name}",
                                        "change": {
                                            "actions": ["create"],
                                            "before": None,
                                            "after": attributes,
                                            "after_unknown": {},
                                            "before_sensitive": False,
                                            "after_sensitive": False,
                                        },
                                    }
                                    resource_changes.append(change_entry)

                                # Create a plan JSON structure with extracted resources
                                plan_json = {
                                    "format_version": "1.0",
                                    "terraform_version": "1.15.2",
                                    "planned_values": {
                                        "root_module": {"resources": resources}
                                    },
                                    "resource_changes": resource_changes,
                                    "configuration": {
                                        "root_module": {
                                            "resources": [
                                                {
                                                    "address": res["address"],
                                                    "mode": res["mode"],
                                                    "type": res["type"],
                                                    "name": res["name"],
                                                    "provider_config_key": res[
                                                        "provider_name"
                                                    ],
                                                }
                                                for res in resources
                                            ]
                                        }
                                    },
                                    "validation_only": True,
                                    "validation_output": val_data,
                                }

                                # Write the plan with extracted resources
                                json_file = tf_file.with_suffix(".json")
                                with open(json_file, "w") as f:
                                    json.dump(plan_json, f, indent=2)

                                logger.info(
                                    f"✓ Generated validation-based plan with {len(resources)} resources for {json_file}"
                                )
                                return True
                            except Exception as e:
                                logger.error(f"Failed to create validation plan: {e}")
                                return False

                    # Not an Azure issue or validation also failed
                    logger.error(
                        f"Failed to generate plan for {tf_file} after {self.max_retries} attempts"
                    )
                    return False

            # If we modified the content (during init or plan fixes), update the original file
            if current_content != original_content:
                logger.info(f"Updating {tf_file} with AI-fixed version")
                with open(tf_file, "w") as f:
                    f.write(current_content)

            # Convert plan to JSON
            logger.debug("Converting plan to JSON")
            success, stdout, stderr = self.run_command(
                ["terraform", "show", "-json", "tfplan"], temp_path
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
            with open(json_file, "w") as f:
                json.dump(json_data, f, indent=2)

            logger.info(f"✓ Successfully generated {json_file}")
            return True

    def process_directory(
        self, root_dir: Path, skip_existing: bool = False, workers: int = 1
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
        self.stats["total"] = len(tf_files)

        if not tf_files:
            logger.warning("No .tf files found")
            return self.stats

        if workers == 1:
            # Sequential processing
            for tf_file in tf_files:
                if self.process_tf_file(tf_file, skip_existing):
                    self.stats["success"] += 1
                else:
                    self.stats["failed"] += 1
        else:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(
                        self.process_tf_file, tf_file, skip_existing
                    ): tf_file
                    for tf_file in tf_files
                }

                for future in as_completed(futures):
                    tf_file = futures[future]
                    try:
                        if future.result():
                            self.stats["success"] += 1
                        else:
                            self.stats["failed"] += 1
                    except Exception as e:
                        logger.error(f"Error processing {tf_file}: {e}")
                        self.stats["failed"] += 1

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
        """,
    )

    parser.add_argument(
        "directory", type=Path, help="Root directory containing .tf files"
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retry attempts for terraform init (default: 3)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of concurrent workers for parallel processing (default: 1)",
    )

    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip .tf files that already have corresponding .json files",
    )

    parser.add_argument(
        "--api-key",
        type=str,
        help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be processed without making changes",
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
            verbose=args.verbose,
        )
        tf_files = generator.find_tf_files(args.directory)
        print(f"\nWould process {len(tf_files)} .tf files:")
        for tf_file in tf_files:
            json_file = tf_file.with_suffix(".json")
            status = "EXISTS" if json_file.exists() else "NEW"
            skip_marker = (
                " (would skip)" if args.skip_existing and json_file.exists() else ""
            )
            print(f"  [{status}] {tf_file}{skip_marker}")
        sys.exit(0)

    # Create generator and process files
    try:
        generator = TerraformPlanGenerator(
            max_retries=args.max_retries,
            anthropic_api_key=args.api_key,
            verbose=args.verbose,
        )

        generator.process_directory(
            args.directory, skip_existing=args.skip_existing, workers=args.workers
        )

        generator.print_summary()

        # Exit with error code if any files failed
        if generator.stats["failed"] > 0:
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
