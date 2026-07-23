#!/usr/bin/env python3
"""
Terraform JSON Plan Generator

This script recursively finds .tf files and generates corresponding JSON plan files.
It uses AI-powered auto-fixing to handle terraform init failures.

Azure (azurerm) note:
    Unlike aws/google/alicloud, the azurerm provider requires a reachable,
    authenticatable ARM + Entra endpoint even at `terraform plan` time — mock
    credentials alone always fail. So azurerm_* files are planned against a local
    Topaz Azure emulator (https://topaz.thecloudtheory.com) started automatically
    in Docker, producing REAL plans fully offline (no real Azure, no credentials).

    Prerequisites for the Azure path (all optional — without them, azurerm_* files
    fall back to a synthetic validation-based plan and this is reported in the
    summary):
      - docker (the script runs the Topaz container itself)
      - az CLI (used for non-interactive login to the emulator)
      - `topaz.local.dev` must resolve to 127.0.0.1. Topaz's metadata document
        points clients at https://topaz.local.dev:8899, so add to /etc/hosts:
            127.0.0.1 topaz.local.dev
    Pass --no-topaz to skip the emulator and always use the synthetic fallback.
"""

import argparse
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
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


class TopazManager:
    """
    Manages a local Topaz Azure emulator so that azurerm_* Terraform files can be
    planned offline, with no real Azure subscription or credentials.

    Unlike aws/google/alicloud, the azurerm provider requires a reachable and
    authenticatable ARM + Entra endpoint even at `terraform plan` time — mock
    ARM_* credentials alone always fail with AADSTS/az-login errors. Topaz
    (https://topaz.thecloudtheory.com) emulates both ARM and Entra locally, so a
    genuine `terraform plan` -> `terraform show -json` succeeds fully offline.

    Note that `terraform plan` for `create` actions of managed resources only
    needs the provider *schema*, not the ARM data-plane, so Topaz's per-service
    coverage rarely matters here — even resources it does not emulate plan fine.
    Coverage only matters for `data` sources (resolved at plan time) against a
    service Topaz doesn't implement, which is the case the caller falls back on.
    """

    # Values are fixed by Topaz and verified against the emulator + its own
    # CI harness (Topaz.Tests.Terraform/TopazFixture.cs). They are stable across
    # container versions (the self-signed cert is committed to the repo).
    RM_PORT = 8899
    PROXY_PORT = 44380
    HOSTNAME = "topaz.local.dev"
    SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000001"
    TENANT_ID = "50717675-3E5E-4A1E-8CB5-C62D8BE8CA48"
    # Default admin user seeded by Topaz's Entra emulator at startup.
    ADMIN_USER = "topazadmin@topaz.local.dev"
    ADMIN_PASSWORD = "admin"
    IMAGE = "thecloudtheory/topaz-host:latest"
    CLOUD_NAME = "TopazPlanGen"
    CLOUD_JSON_URL = (
        "https://raw.githubusercontent.com/TheCloudTheory/Topaz/refs/heads/main/cloud.json"
    )
    METADATA_PATH = "/metadata/endpoints?api-version=2022-09-01"

    def __init__(self, container_name: str = "topaz-plan-gen"):
        self.container_name = container_name
        self.work_dir = Path(tempfile.mkdtemp(prefix="topaz-plangen-"))
        self.ca_bundle: Optional[Path] = None
        self.ready = False
        self._started_container = False

    # ---- lifecycle -----------------------------------------------------

    def start(self) -> bool:
        """
        Start the Topaz container, trust its cert, and perform a non-interactive
        `az login`. Returns True if the emulator is ready for azurerm plans.
        """
        if shutil.which("docker") is None:
            logger.warning(
                "Docker not found; cannot start Topaz. azurerm_* files will fall "
                "back to synthetic plans."
            )
            return False
        if shutil.which("az") is None:
            logger.warning(
                "Azure CLI (az) not found; cannot authenticate to Topaz. azurerm_* "
                "files will fall back to synthetic plans."
            )
            return False
        if not self._dns_ok():
            logger.warning(
                f"'{self.HOSTNAME}' does not resolve to a loopback address. Topaz's "
                f"metadata document points terraform/az at 'https://{self.HOSTNAME}:"
                f"{self.RM_PORT}', so this host must map to 127.0.0.1. Add this line "
                f"to /etc/hosts (requires sudo):\n"
                f"    127.0.0.1 {self.HOSTNAME}\n"
                f"Falling back to synthetic plans for azurerm_* files until then."
            )
            return False

        try:
            self._run_container()
            if not self._wait_ready():
                logger.error("Topaz did not become ready in time")
                self.stop()
                return False
            self._prepare_ca_bundle()
            if not self._az_login():
                logger.error("Failed to authenticate az CLI against Topaz")
                self.stop()
                return False
        except Exception as e:
            logger.error(f"Failed to start Topaz: {e}")
            self.stop()
            return False

        self.ready = True
        logger.info("Topaz emulator ready — azurerm plans will run against it")
        return True

    def _dns_ok(self) -> bool:
        """True if HOSTNAME resolves to a loopback address (127.0.0.1 / ::1)."""
        import socket

        try:
            infos = socket.getaddrinfo(self.HOSTNAME, self.RM_PORT)
        except socket.gaierror:
            return False
        for info in infos:
            addr = info[4][0]
            if addr.startswith("127.") or addr == "::1":
                return True
        return False

    def _run_container(self) -> None:
        # Remove any stale container from a previous run, then start fresh.
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True,
            text=True,
        )
        cmd = [
            "docker", "run", "-d",
            "--name", self.container_name,
            "-p", f"{self.RM_PORT}:{self.RM_PORT}",
            "-p", f"{self.PROXY_PORT}:{self.PROXY_PORT}",
            self.IMAGE,
            "--default-subscription", self.SUBSCRIPTION_ID,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {result.stderr.strip()}")
        self._started_container = True
        logger.info(f"Started Topaz container '{self.container_name}'")

    def _wait_ready(self, timeout: int = 60) -> bool:
        """Poll the metadata endpoint (via localhost) until Topaz responds."""
        import ssl
        import urllib.error

        url = f"https://localhost:{self.RM_PORT}{self.METADATA_PATH}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # readiness probe only; not used for planning
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3, context=ctx) as resp:
                    if resp.status == 200:
                        return True
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            time.sleep(1)
        return False

    def _extract_cert(self) -> Path:
        """Fetch the cert Topaz is serving via a TLS handshake (container is distroless)."""
        import ssl

        pem = ssl.get_server_certificate(("localhost", self.RM_PORT))
        cert_path = self.work_dir / "topaz.crt"
        cert_path.write_text(pem)
        return cert_path

    def _prepare_ca_bundle(self) -> None:
        """
        Build a CA bundle (system CAs + Topaz cert) for the `az` subprocess, and
        trust the Topaz cert for the terraform provider's own HTTPS client.

        terraform (Go) on macOS reads the system keychain, while on Linux it
        honours SSL_CERT_FILE; the `az` CLI (Python) always honours
        REQUESTS_CA_BUNDLE. We cover all three.
        """
        cert_path = self._extract_cert()

        # Combined bundle for az (Python/requests) and Go-on-Linux.
        system_ca = self._system_ca_path()
        bundle = self.work_dir / "topaz-ca-bundle.pem"
        parts = []
        if system_ca and Path(system_ca).exists():
            parts.append(Path(system_ca).read_text())
        parts.append(cert_path.read_text())
        bundle.write_text("\n".join(parts))
        self.ca_bundle = bundle

        # On macOS, terraform's Go HTTP client uses the login keychain, not
        # SSL_CERT_FILE, so trust the cert there. Idempotent: re-adding a trusted
        # cert is a no-op.
        if platform.system() == "Darwin":
            keychain = (
                Path.home() / "Library" / "Keychains" / "login.keychain-db"
            )
            subprocess.run(
                [
                    "security", "add-trusted-cert", "-r", "trustRoot",
                    "-k", str(keychain), str(cert_path),
                ],
                capture_output=True,
                text=True,
            )

    @staticmethod
    def _system_ca_path() -> Optional[str]:
        """Best-effort path to the system/az CA bundle to prepend to ours."""
        try:
            import certifi

            return certifi.where()
        except Exception:
            for candidate in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
                if Path(candidate).exists():
                    return candidate
        return None

    def _az_env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env["AZURE_CORE_INSTANCE_DISCOVERY"] = "false"
        env["HTTPS_PROXY"] = f"http://127.0.0.1:{self.PROXY_PORT}"
        if self.ca_bundle:
            env["REQUESTS_CA_BUNDLE"] = str(self.ca_bundle)
        return env

    def _az_login(self) -> bool:
        """Register the Topaz cloud and log in non-interactively (ROPC)."""
        env = self._az_env()

        cloud_json = self.work_dir / "cloud.json"
        try:
            urllib.request.urlretrieve(self.CLOUD_JSON_URL, cloud_json)
        except Exception as e:
            logger.error(f"Failed to download Topaz cloud.json: {e}")
            return False

        # Register (or update, if a previous run left it) then activate the cloud.
        reg = subprocess.run(
            ["az", "cloud", "register", "-n", self.CLOUD_NAME,
             "--cloud-config", f"@{cloud_json}"],
            capture_output=True, text=True, env=env,
        )
        if reg.returncode != 0:
            subprocess.run(
                ["az", "cloud", "update", "-n", self.CLOUD_NAME,
                 "--cloud-config", f"@{cloud_json}"],
                capture_output=True, text=True, env=env,
            )
        subprocess.run(
            ["az", "cloud", "set", "-n", self.CLOUD_NAME],
            capture_output=True, text=True, env=env,
        )

        login = subprocess.run(
            ["az", "login", "--username", self.ADMIN_USER,
             "--password", self.ADMIN_PASSWORD],
            capture_output=True, text=True, env=env, timeout=60,
        )
        if login.returncode != 0:
            logger.error(f"az login against Topaz failed: {login.stderr.strip()[:300]}")
            return False
        return True

    def terraform_env(self, base_env: Dict[str, str]) -> Dict[str, str]:
        """
        Return env vars (merged onto base_env) that route a `terraform plan` for
        azurerm resources at the running Topaz emulator.
        """
        env = dict(base_env)
        env["ARM_SUBSCRIPTION_ID"] = self.SUBSCRIPTION_ID
        env["ARM_TENANT_ID"] = self.TENANT_ID
        env["AZURE_CORE_INSTANCE_DISCOVERY"] = "false"
        # The azurerm provider shells out to `az account get-access-token`, so the
        # az subprocess needs the Topaz CA too — easy to miss and the failure mode
        # (CERTIFICATE_VERIFY_FAILED at plan time) is confusing.
        if self.ca_bundle:
            env["REQUESTS_CA_BUNDLE"] = str(self.ca_bundle)
        # Don't leak an ARM_CLIENT_ID/SECRET from the generic env — that would make
        # the provider try service-principal auth instead of the CLI session.
        for stale in ("ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_SKIP_PROVIDER_REGISTRATION"):
            env.pop(stale, None)
        return env

    # Provider block to inject for azurerm files routed through Topaz (v4 syntax).
    def provider_block(self) -> str:
        return f"""provider "azurerm" {{
     features {{}}
     metadata_host                   = "{self.HOSTNAME}:{self.RM_PORT}"
     resource_provider_registrations = "none"
   }}"""

    def stop(self) -> None:
        if self._started_container:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True, text=True,
            )
            self._started_container = False
        shutil.rmtree(self.work_dir, ignore_errors=True)
        self.ready = False


class TerraformPlanGenerator:
    """Handles Terraform plan generation with AI-powered error fixing."""

    def __init__(
        self,
        max_retries: int = 3,
        anthropic_api_key: Optional[str] = None,
        verbose: bool = False,
        use_topaz: bool = True,
    ):
        """
        Initialize the generator.

        Args:
            max_retries: Maximum number of retry attempts for terraform init
            anthropic_api_key: API key for Claude (defaults to ANTHROPIC_API_KEY env var)
            verbose: Enable verbose logging
            use_topaz: Route azurerm_* files through a local Topaz emulator so real
                plans can be generated offline (falls back to synthetic if it can't
                start). When False, azurerm always uses the synthetic fallback.
        """
        self.max_retries = max_retries
        self.verbose = verbose
        self.use_topaz = use_topaz
        # Lazily started the first time an azurerm file is processed, so runs with
        # no Azure rules never pay the container startup cost. A lock guards startup
        # so parallel workers share a single container instead of racing on ports.
        self.topaz: Optional[TopazManager] = None
        self._topaz_attempted = False
        self._topaz_lock = threading.Lock()

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

        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
            # azurerm-specific: real plans via Topaz vs. synthetic fallback.
            "azure_topaz_plans": 0,
            "azure_synthetic_fallback": 0,
        }

        # The nifcloud provider's registry entry points at GitHub release
        # assets that no longer exist (the nifcloud org made its repos
        # private), so `terraform init` can never fetch it normally. We
        # build it ourselves from the Go module proxy (which mirrors the
        # source independently of GitHub) and point Terraform at it via a
        # scoped filesystem_mirror, so only nifcloud bypasses the registry.
        self.nifcloud_tf_cli_config: Optional[Path] = self._ensure_nifcloud_provider()

    # Version to build/mirror. Matches the last version published to the
    # registry before the upstream GitHub org went private.
    NIFCLOUD_PROVIDER_VERSION = "1.18.0"
    NIFCLOUD_MODULE_PATH = "github.com/nifcloud/terraform-provider-nifcloud"

    @staticmethod
    def _terraform_platform() -> str:
        """Return the Terraform-style '<os>_<arch>' string for this machine."""
        os_name = platform.system().lower()
        arch = platform.machine().lower()
        arch_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
        return f"{os_name}_{arch_map.get(arch, arch)}"

    def _ensure_nifcloud_provider(self) -> Optional[Path]:
        """
        Build the nifcloud Terraform provider from source (via the Go module
        proxy) if it isn't already built, register it in a local filesystem
        mirror, and return a Terraform CLI config file that routes only
        nifcloud/nifcloud installs to that mirror.

        Returns:
            Path to a generated .terraformrc file, or None if the provider
            could not be built (e.g. Go toolchain unavailable).
        """
        cache_dir = Path.home() / ".cache" / "generate_tf_plans" / "nifcloud"
        platform_dir = (
            cache_dir
            / "mirror"
            / "registry.terraform.io"
            / "nifcloud"
            / "nifcloud"
            / self.NIFCLOUD_PROVIDER_VERSION
            / self._terraform_platform()
        )
        binary_path = platform_dir / f"terraform-provider-nifcloud_v{self.NIFCLOUD_PROVIDER_VERSION}"
        cli_config_path = cache_dir / "cli_config.tfrc"

        if binary_path.exists():
            logger.debug(f"nifcloud provider already built at {binary_path}")
            self._write_nifcloud_cli_config(cli_config_path, cache_dir / "mirror")
            return cli_config_path

        if shutil.which("go") is None:
            logger.warning(
                "Go toolchain not found; cannot build the nifcloud provider "
                "locally. .tf files using nifcloud_* resources will fail to init."
            )
            return None

        logger.info(
            f"Building nifcloud provider v{self.NIFCLOUD_PROVIDER_VERSION} from source "
            "(registry release assets are unavailable upstream)..."
        )

        try:
            with tempfile.TemporaryDirectory() as build_tmp:
                build_path = Path(build_tmp)
                zip_url = (
                    f"https://proxy.golang.org/{self.NIFCLOUD_MODULE_PATH}/@v/"
                    f"v{self.NIFCLOUD_PROVIDER_VERSION}.zip"
                )
                zip_path = build_path / "src.zip"
                urllib.request.urlretrieve(zip_url, zip_path)

                with zipfile.ZipFile(zip_path) as zf:
                    zf.extractall(build_path)

                src_dir = (
                    build_path
                    / self.NIFCLOUD_MODULE_PATH
                    / f"@v{self.NIFCLOUD_PROVIDER_VERSION}"
                )
                if not src_dir.exists():
                    # Module proxy sometimes lowercases path segments differently.
                    candidates = list(build_path.glob("**/go.mod"))
                    if not candidates:
                        raise RuntimeError("Could not locate extracted provider source")
                    src_dir = candidates[0].parent

                platform_dir.mkdir(parents=True, exist_ok=True)
                env = os.environ.copy()
                env["GOFLAGS"] = "-mod=mod"
                result = subprocess.run(
                    ["go", "build", "-o", str(binary_path), "."],
                    cwd=src_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    logger.error(f"Failed to build nifcloud provider: {result.stderr[:500]}")
                    return None

                binary_path.chmod(0o755)
        except Exception as e:
            logger.error(f"Failed to fetch/build nifcloud provider: {e}")
            return None

        logger.info(f"Built nifcloud provider at {binary_path}")
        self._write_nifcloud_cli_config(cli_config_path, cache_dir / "mirror")
        return cli_config_path

    @staticmethod
    def _write_nifcloud_cli_config(cli_config_path: Path, mirror_dir: Path) -> None:
        """Write a Terraform CLI config that mirrors only nifcloud/nifcloud locally."""
        cli_config_path.parent.mkdir(parents=True, exist_ok=True)
        cli_config_path.write_text(
            f"""provider_installation {{
  filesystem_mirror {{
    path    = "{mirror_dir}"
    include = ["nifcloud/nifcloud"]
  }}
  direct {{
    exclude = ["nifcloud/nifcloud"]
  }}
}}
"""
        )

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
        self,
        cmd: List[str],
        cwd: Path,
        timeout: int = 300,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, str, str]:
        """
        Run a shell command and return success status and output.

        Args:
            cmd: Command and arguments as a list
            cwd: Working directory
            timeout: Command timeout in seconds
            extra_env: Overrides merged onto the base environment. When provided
                (e.g. by the Topaz azurerm path), the caller controls all ARM_*
                variables and the default mock Azure credentials are NOT applied.

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

            if extra_env is None:
                # Default (non-Topaz) path: set mock Azure environment variables so
                # the azurerm provider config doesn't error on missing values.
                # (This is enough for init/validate but NOT for a real azurerm plan.)
                env["ARM_SKIP_PROVIDER_REGISTRATION"] = "true"
                env["ARM_SUBSCRIPTION_ID"] = "00000000-0000-0000-0000-000000000000"
                env["ARM_TENANT_ID"] = "00000000-0000-0000-0000-000000000000"
                env["ARM_CLIENT_ID"] = "00000000-0000-0000-0000-000000000000"
                env["ARM_CLIENT_SECRET"] = "mock_secret_value"
            else:
                env.update(extra_env)

            if self.nifcloud_tf_cli_config is not None:
                env["TF_CLI_CONFIG_FILE"] = str(self.nifcloud_tf_cli_config)

            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
            )
            success = result.returncode == 0
            return success, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", str(e)

    def _ensure_topaz(self) -> Optional["TopazManager"]:
        """
        Lazily start the Topaz emulator on first azurerm file. Returns the manager
        if it's ready, or None if Topaz is disabled or failed to start (caller then
        falls back to a synthetic plan).
        """
        if not self.use_topaz:
            return None
        with self._topaz_lock:
            if self.topaz is not None:
                return self.topaz if self.topaz.ready else None
            if self._topaz_attempted:
                return None

            self._topaz_attempted = True
            manager = TopazManager()
            if manager.start():
                self.topaz = manager
                return manager
            # start() already tore itself down and logged the reason.
            return None

    # Maps a resource type prefix to its provider source and mock provider block.
    PROVIDER_HINTS = {
        "aws": (
            "hashicorp/aws",
            '~> 4.0',
            """provider "aws" {
     access_key                  = "mock_access_key"
     secret_key                  = "mock_secret_key"
     region                      = "us-east-1"
     skip_credentials_validation = true
     skip_requesting_account_id  = true
     skip_metadata_api_check     = true
   }""",
        ),
        "google": (
            "hashicorp/google",
            "~> 4.0",
            """provider "google" {
     project     = "mock-project"
     region      = "us-central1"
     credentials = jsonencode({ type = "service_account" })
   }""",
        ),
        "alicloud": (
            "aliyun/alicloud",
            "~> 1.0",
            """provider "alicloud" {
     access_key = "mock_access_key"
     secret_key = "mock_secret_key"
     region     = "cn-hangzhou"
   }""",
        ),
        "nifcloud": (
            "nifcloud/nifcloud",
            NIFCLOUD_PROVIDER_VERSION,
            """provider "nifcloud" {
     access_key = "mock_access_key"
     secret_key = "mock_secret_key"
     region     = "jp-east-1"
   }""",
        ),
        "azurerm": (
            "hashicorp/azurerm",
            "~> 4.0",
            """provider "azurerm" {
     features {}
     metadata_host                   = "topaz.local.dev:8899"
     resource_provider_registrations = "none"
     # Plans run against a local Topaz emulator (see TopazManager); no real Azure.
   }""",
        ),
    }

    def detect_provider(self, tf_content: str) -> Optional[str]:
        """
        Detect the intended provider from the resource/data types used in the file,
        e.g. `nifcloud_router` -> "nifcloud", `aws_security_group` -> "aws".

        Args:
            tf_content: Terraform file content

        Returns:
            The detected provider prefix, or None if it can't be determined.
        """
        import re

        types = re.findall(r'(?:resource|data)\s+"([a-zA-Z0-9]+)_', tf_content)
        if not types:
            return None

        # Prefer known providers, sorted by first appearance.
        for candidate in types:
            if candidate in self.PROVIDER_HINTS:
                return candidate

        # Fall back to the most common prefix even if we have no canned hint for it.
        from collections import Counter

        return Counter(types).most_common(1)[0][0]

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

        provider = self.detect_provider(tf_content)
        hint = self.PROVIDER_HINTS.get(provider) if provider else None

        if hint:
            source, version, provider_block = hint
            provider_guidance = f"""CRITICAL: The resources in this file belong to the "{provider}" provider. Do NOT switch them to a different provider (e.g. do not rewrite {provider}_* resources as aws_* resources). Keep every resource type and name exactly as in the original file.

Add or fix the required provider block:
   terraform {{
     required_providers {{
       {provider} = {{
         source  = "{source}"
         version = "{version}"
       }}
     }}
   }}

   {provider_block}
"""
        elif provider:
            provider_guidance = f"""CRITICAL: The resources in this file belong to the "{provider}" provider. Do NOT switch them to a different provider (e.g. do not rewrite {provider}_* resources as aws_* resources). Keep every resource type and name exactly as in the original file.

Add a terraform {{ required_providers {{ ... }} }} block and a provider "{provider}" {{ ... }} block with mock/fake credentials so that terraform init and plan succeed without real authentication.
"""
        else:
            provider_guidance = ""

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

Fix this error.

{provider_guidance}
Keep ALL original resources from the file, with their original resource types and provider - only add the missing terraform/provider blocks and any missing stub dependencies above them.

NOTE: azurerm_* files are planned against a LOCAL Topaz Azure emulator (no real Azure, no credentials). If (and only if) the resources in this file are azurerm_* resources, use this approach:
1. Use the azurerm v4 provider pointed at the local emulator:
   terraform {{
     required_providers {{
       azurerm = {{
         source = "hashicorp/azurerm"
         version = "~> 4.0"
       }}
       random = {{
         source = "hashicorp/random"
         version = "~> 3.0"
       }}
     }}
   }}

   provider "azurerm" {{
     features {{}}
     metadata_host                   = "topaz.local.dev:8899"
     resource_provider_registrations = "none"
   }}

2. Use azurerm v4 attribute names (they changed from v3), e.g.:
   - `enable_non_ssl_port` -> `non_ssl_port_enabled`
   - `skip_provider_registration` -> `resource_provider_registrations = "none"`
   Keep every other original attribute exactly as-is.

3. Add stub resources for any referenced but undefined resources:
   resource "azurerm_resource_group" "example" {{
     name     = "test-rg"
     location = "eastus"
   }}

   resource "random_id" "server" {{
     byte_length = 8
   }}

4. AVOID adding `data` sources (e.g. data "azurerm_subscription", data "azurerm_client_config"). Data sources are resolved at plan time and require services the emulator may not implement. Only keep a data source if the ORIGINAL file already had one and a resource references it; otherwise do not introduce new ones.

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

{provider_guidance}
If the error involves Azure (missing resources or provider), azurerm_* files are planned against a LOCAL Topaz Azure emulator (no real Azure, no credentials). Add:
   terraform {{
     required_providers {{
       azurerm = {{
         source = "hashicorp/azurerm"
         version = "~> 4.0"
       }}
       random = {{
         source = "hashicorp/random"
         version = "~> 3.0"
       }}
     }}
   }}

   provider "azurerm" {{
     features {{}}
     metadata_host                   = "topaz.local.dev:8899"
     resource_provider_registrations = "none"
   }}

   # Add stub resources for common references:
   resource "azurerm_resource_group" "example" {{
     name     = "test-rg"
     location = "eastus"
   }}

   resource "random_id" "server" {{
     byte_length = 8
   }}

Use azurerm v4 attribute names (e.g. `enable_non_ssl_port` -> `non_ssl_port_enabled`). Do NOT add new `data` sources (azurerm_subscription, azurerm_client_config, etc.) — they need services the emulator may not implement.

Otherwise, do NOT change any resource types or provider - keep every original resource exactly as-is and only add/fix the terraform/provider configuration blocks needed to make init succeed.

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

        For azurerm_* files this routes `terraform plan` through a local Topaz
        emulator so a real plan is produced offline; if Topaz is unavailable or a
        plan can't be produced (e.g. a data source against a service Topaz doesn't
        emulate), it falls back to a synthetic plan and records that the Topaz path
        failed. All other providers use the normal plan path.

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

        with open(tf_file, "r") as f:
            provider = self.detect_provider(f.read())
        is_azure = provider == "azurerm"

        # For azurerm, start (once) and route through Topaz so plan succeeds offline.
        topaz = self._ensure_topaz() if is_azure else None
        extra_env = topaz.terraform_env(os.environ.copy()) if topaz else None

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

                success, stdout, stderr = self.run_command(
                    ["terraform", "init"], temp_path, extra_env=extra_env
                )

                if success:
                    logger.debug("Terraform init successful")
                    break

                logger.warning(
                    f"Terraform init failed (attempt {attempt}): {stderr[:200]}"
                )

                if attempt < self.max_retries:
                    fixed_content = self.fix_terraform_with_ai(
                        current_content, stderr, attempt
                    )
                    if fixed_content:
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

            # Try terraform plan with retries
            for plan_attempt in range(1, self.max_retries + 1):
                logger.debug(f"Terraform plan attempt {plan_attempt}/{self.max_retries}")

                success, stdout, stderr = self.run_command(
                    ["terraform", "plan", "-out=tfplan"], temp_path, extra_env=extra_env
                )

                if success:
                    logger.debug("Terraform plan successful")
                    break

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
                        with open(temp_tf, "w") as f:
                            f.write(fixed_content)
                        current_content = fixed_content
                        logger.info("Applied AI fix for plan error, retrying...")

                        # Re-run init in case providers/deps changed.
                        reinit_success, _, _ = self.run_command(
                            ["terraform", "init", "-upgrade"], temp_path, extra_env=extra_env
                        )
                        if not reinit_success:
                            logger.warning(
                                "Re-init after plan fix failed, continuing anyway..."
                            )
                    else:
                        logger.error("AI fix for plan error failed")
                        return False
                else:
                    # All plan attempts exhausted.
                    if is_azure:
                        # Topaz couldn't produce a real plan for this file (unsupported
                        # data source, unemulated service, etc.). Fall back to a
                        # synthetic plan so the rule still gets a fixture, and record
                        # that the Topaz path failed so it's visible in the summary.
                        reason = "Topaz enabled but plan failed" if topaz else (
                            "Topaz unavailable" if self.use_topaz else "Topaz disabled"
                        )
                        logger.warning(
                            f"Azure plan via Topaz did not succeed for {tf_file} "
                            f"({reason}); falling back to a synthetic plan. "
                            f"Last error: {stderr[:200]}"
                        )
                        if self._write_synthetic_azure_plan(
                            tf_file, json_file, current_content, temp_path,
                            extra_env=extra_env,
                        ):
                            self.stats["azure_synthetic_fallback"] += 1
                            return True

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
                ["terraform", "show", "-json", "tfplan"], temp_path, extra_env=extra_env
            )

            if not success:
                logger.error(f"Terraform show failed: {stderr[:200]}")
                return False

            try:
                json_data = json.loads(stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON output: {e}")
                return False

            with open(json_file, "w") as f:
                json.dump(json_data, f, indent=2)

            if is_azure:
                self.stats["azure_topaz_plans"] += 1
            logger.info(f"✓ Successfully generated {json_file}")
            return True

    # --- Attribute extraction for the synthetic-plan fallback ----------------

    # Simple `attr = "value"` / `attr = number|bool` patterns, keyed by attr name.
    _SYNTHETIC_ATTR_PATTERNS = [
        (r'name\s*=\s*"([^"]+)"', "name"),
        (r'location\s*=\s*"([^"]+)"', "location"),
        (r'resource_group_name\s*=\s*"([^"]+)"', "resource_group_name"),
        (r"capacity\s*=\s*(\d+)", "capacity"),
        (r'family\s*=\s*"([^"]+)"', "family"),
        (r'sku_name\s*=\s*"([^"]+)"', "sku_name"),
        (r"enable_non_ssl_port\s*=\s*(true|false)", "enable_non_ssl_port"),
        (r"non_ssl_port_enabled\s*=\s*(true|false)", "non_ssl_port_enabled"),
        (r'minimum_tls_version\s*=\s*"([^"]+)"', "minimum_tls_version"),
        (r'min_tls_version\s*=\s*"([^"]+)"', "min_tls_version"),
        (r'start_ip\s*=\s*"([^"]+)"', "start_ip"),
        (r'end_ip\s*=\s*"([^"]+)"', "end_ip"),
        # Alicloud specific
        (r'zone_id\s*=\s*"([^"]+)"', "zone_id"),
        (r'instance_type\s*=\s*"([^"]+)"', "instance_type"),
        (r'vswitch_id\s*=\s*"([^"]+)"', "vswitch_id"),
        (r"security_groups\s*=\s*\[([^\]]+)\]", "security_groups"),
        (r"internet_max_bandwidth_out\s*=\s*(\d+)", "internet_max_bandwidth_out"),
        # AWS specific
        (r'ami\s*=\s*"([^"]+)"', "ami"),
        (r'vpc_id\s*=\s*"([^"]+)"', "vpc_id"),
        (r'subnet_id\s*=\s*"([^"]+)"', "subnet_id"),
    ]

    # References to other resources → a concrete default value.
    _SYNTHETIC_REF_PATTERNS = [
        (r"location\s*=\s*azurerm_resource_group\.[^.]+\.location", "location", "eastus"),
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

    def _extract_synthetic_resources(self, tf_content: str):
        """
        Parse resource blocks out of Terraform content and return
        (planned_resources, resource_changes) lists shaped like a real
        `terraform show -json` plan. Best-effort, regex-based — only used for the
        azurerm fallback when a real Topaz plan couldn't be produced.
        """
        import re

        resources = []
        resource_changes = []

        resource_pattern = (
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        )
        for match in re.finditer(resource_pattern, tf_content, re.DOTALL):
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)

            attributes: Dict = {}
            for pattern, attr_name in self._SYNTHETIC_ATTR_PATTERNS:
                m = re.search(pattern, resource_body)
                if not m:
                    continue
                value = m.group(1)
                if value in ("true", "false"):
                    value = value == "true"
                elif value.isdigit():
                    value = int(value)
                attributes[attr_name] = value

            for pattern, attr_name, default_value in self._SYNTHETIC_REF_PATTERNS:
                if re.search(pattern, resource_body) and attr_name not in attributes:
                    attributes[attr_name] = default_value

            # Nested redis_configuration block, if present.
            config_match = re.search(
                r"redis_configuration\s*\{([^}]+)\}", resource_body
            )
            if config_match:
                redis_config = {}
                config_body = config_match.group(1)
                for pattern, attr_name in [
                    (r"maxclients\s*=\s*(\d+)", "maxclients"),
                    (r"maxmemory_reserved\s*=\s*(\d+)", "maxmemory_reserved"),
                    (r"maxmemory_delta\s*=\s*(\d+)", "maxmemory_delta"),
                    (r'maxmemory_policy\s*=\s*"([^"]+)"', "maxmemory_policy"),
                ]:
                    m = re.search(pattern, config_body)
                    if m:
                        val = m.group(1)
                        redis_config[attr_name] = int(val) if val.isdigit() else val
                if redis_config:
                    attributes["redis_configuration"] = [redis_config]

            provider_name = (
                resource_type.split("_")[0] if "_" in resource_type else "null"
            )

            resources.append(
                {
                    "address": f"{resource_type}.{resource_name}",
                    "mode": "managed",
                    "type": resource_type,
                    "name": resource_name,
                    "provider_name": provider_name,
                    "schema_version": 0,
                    "values": attributes,
                    "sensitive_values": {},
                }
            )
            resource_changes.append(
                {
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
            )

        return resources, resource_changes

    def _write_synthetic_azure_plan(
        self,
        tf_file: Path,
        json_file: Path,
        tf_content: str,
        temp_path: Path,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Write a synthetic plan JSON for an azurerm file when a real Topaz plan
        couldn't be produced. Runs `terraform validate` first (schema-level, needs
        no auth) so the config is at least valid, then emits a plan-shaped JSON
        with resources parsed from the HCL. Returns True on success.
        """
        val_success, val_stdout, _ = self.run_command(
            ["terraform", "validate", "-json"], temp_path, extra_env=extra_env
        )
        if not val_success:
            logger.error(
                f"terraform validate failed for {tf_file}; cannot build synthetic plan"
            )
            return False

        try:
            val_data = json.loads(val_stdout) if val_stdout else {}
            resources, resource_changes = self._extract_synthetic_resources(tf_content)

            plan_json = {
                "format_version": "1.0",
                "terraform_version": "1.15.2",
                "planned_values": {"root_module": {"resources": resources}},
                "resource_changes": resource_changes,
                "configuration": {
                    "root_module": {
                        "resources": [
                            {
                                "address": res["address"],
                                "mode": res["mode"],
                                "type": res["type"],
                                "name": res["name"],
                                "provider_config_key": res["provider_name"],
                            }
                            for res in resources
                        ]
                    }
                },
                # Marks this as a schema-validated synthetic plan (not a real
                # terraform plan) so consumers can tell the two apart.
                "validation_only": True,
                "validation_output": val_data,
            }

            with open(json_file, "w") as f:
                json.dump(plan_json, f, indent=2)

            logger.info(
                f"✓ Generated synthetic (validation-based) plan with "
                f"{len(resources)} resources for {json_file}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to create synthetic plan: {e}")
            return False


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

        # A single shared Topaz container serves every azurerm file. Start it once
        # up front (if any azurerm files are present) so parallel workers don't race
        # to bind its ports, and always tear it down when we're done.
        if self.use_topaz and any(self._file_is_azure(tf) for tf in tf_files):
            self._ensure_topaz()

        try:
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
        finally:
            self.close()

        return self.stats

    @staticmethod
    def _file_is_azure(tf_file: Path) -> bool:
        try:
            return "azurerm_" in tf_file.read_text()
        except OSError:
            return False

    def close(self) -> None:
        """Tear down the Topaz emulator if it was started."""
        if self.topaz is not None:
            self.topaz.stop()
            self.topaz = None

    def print_summary(self):
        """Print processing summary."""
        print("\n" + "=" * 60)
        print("PROCESSING SUMMARY")
        print("=" * 60)
        print(f"Total files:      {self.stats['total']}")
        print(f"✓ Success:        {self.stats['success']}")
        print(f"✗ Failed:         {self.stats['failed']}")
        print(f"⊘ Skipped:        {self.stats['skipped']}")
        azure_real = self.stats.get("azure_topaz_plans", 0)
        azure_synth = self.stats.get("azure_synthetic_fallback", 0)
        if azure_real or azure_synth:
            print("-" * 60)
            print(f"  Azure real plans (Topaz):     {azure_real}")
            print(f"  Azure synthetic (fallback):   {azure_synth}")
            if azure_synth:
                print(
                    "  ⚠ Synthetic fallbacks were used — those Azure fixtures are\n"
                    "    NOT real terraform plans (Topaz could not plan them)."
                )
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

    parser.add_argument(
        "--no-topaz",
        action="store_true",
        help=(
            "Disable the local Topaz Azure emulator. azurerm_* files then use the "
            "synthetic (validation-based) plan fallback instead of real plans. "
            "By default Topaz is used (requires docker + az CLI)."
        ),
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
            use_topaz=not args.no_topaz,
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
    generator = None
    try:
        generator = TerraformPlanGenerator(
            max_retries=args.max_retries,
            anthropic_api_key=args.api_key,
            verbose=args.verbose,
            use_topaz=not args.no_topaz,
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
    finally:
        # Defensive: process_directory tears Topaz down itself, but ensure the
        # container never leaks if we exit via an interrupt or early error.
        if generator is not None:
            generator.close()


if __name__ == "__main__":
    main()
