# Framework Sync

Syncs framework mappings for IAC rules from the security-monitoring repository.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python sync_framework_mappings.py --source ~/dd/security-monitoring
```

The script will:
- Extract `iacRules` mappings from framework TOML files
- Update `metadata.json` files in the KICS repository with framework mappings
- Prioritize `posture-management-test` over `posture-management/production`
- Replace existing `defaultFrameworks` entries with current mappings
- Clean up orphaned framework mappings from rules that no longer have `iacRules`

## Options

- `--source`: Path to security-monitoring repo (default: `~/dd/security-monitoring`)
- `--kics-dir`: Path to KICS repository directory (default: `../`)
- `--dry-run`: Preview changes without making them
- `--verbose`: Show detailed output