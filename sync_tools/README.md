# Upstream Metadata Sync Guide - Datadog KICS Fork

## 📊 Overview

This guide helps you sync metadata fields from the upstream Checkmarx KICS repository to our Datadog fork. The sync script is flexible and can update any field in `metadata.json` files while preserving our Datadog-specific customizations.

## 🎯 Common Use Cases

### 1. Sync CWE Values
CWE (Common Weakness Enumeration) provides standardized vulnerability classification:
```bash
python3 sync_tools/sync_metadata_from_upstream.py --field cwe
```

### 2. Sync Any Other Field
The script is generic and works with any metadata field:
```bash
python3 sync_tools/sync_metadata_from_upstream.py --field <field_name>
```

## 🚀 Quick Start

### Step 1: Preview Changes (Dry Run)

Always start with a dry run to see what would be updated:

```bash
# Preview CWE sync for all platforms
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --dry-run

# Preview for specific platform
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --dry-run --platform cloudFormation

# Preview for specific provider
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --dry-run --platform cloudFormation --provider aws

# Preview first 10 files only (for testing)
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --dry-run --limit 10
```

### Step 2: Apply Changes

Once you're satisfied with the preview:

```bash
# Sync CWE for all rules
python3 sync_tools/sync_metadata_from_upstream.py --field cwe

# Sync for specific platform
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform cloudFormation

# Sync for specific provider
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform terraform --provider aws
```

## 📋 Command-Line Options

```bash
python3 sync_tools/sync_metadata_from_upstream.py [OPTIONS]

Required:
  --field FIELD         Field name to sync (default: cwe)
                        Common fields: cwe

Optional:
  --dry-run            Preview changes without modifying files
  --platform PLATFORM  Filter by platform (cloudFormation, terraform, k8s, etc.)
  --provider PROVIDER  Filter by cloud provider (aws, azure, gcp, etc.)
  --limit N            Limit number of files to process (useful for testing)
```

## 🎨 Example Workflows

```bash
# 1. Preview changes
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform cloudFormation --dry-run

# 2. Apply if satisfied
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform cloudFormation

```

## 🔧 How It Works

### What the Script Does

✅ **Finds empty fields** - Locates all `metadata.json` files with empty or missing field values  
✅ **Fetches from upstream** - Downloads corresponding file from Checkmarx KICS repository  
✅ **Updates selectively** - Only updates the specified field if upstream has a value  
✅ **Preserves customizations** - Keeps all Datadog-specific fields intact  
✅ **Shows progress** - Provides detailed output and statistics  

### What the Script Doesn't Do

❌ **Won't overwrite existing values** - Skips files that already have the field populated  
❌ **Won't modify other fields** - Only touches the field you specify  
❌ **Won't change query logic** - Only updates metadata, not the actual query code  
❌ **Won't delete or create rules** - Only updates existing metadata  

### Preserved Fields

Your Datadog-specific customizations are always preserved:
- ✅ `descriptionText` - The enhanced descriptions
- ✅ `descriptionUrl` - Links to docs.datadoghq.com
- ✅ `descriptionID` - Internal Datadog IDs

## 📊 Understanding the Output

### Example Output

```
🔄 Syncing 'cwe' field from upstream Checkmarx KICS
================================================================================
📂 Scanning for metadata.json files in assets/queries...
🔍 Filtered to platform: cloudFormation
📊 Found 270 metadata.json files

  🔍 Checking: assets/queries/cloudFormation/aws/s3_bucket_without_ssl/metadata.json
  ✅ cwe: 319

  🔍 Checking: assets/queries/cloudFormation/aws/docdb_password_plaintext/metadata.json
  ✅ cwe: 256

  🔍 Checking: assets/queries/cloudFormation/aws/custom_rule/metadata.json
  ⚠️  Not found in upstream

  🔍 Checking: assets/queries/cloudFormation/aws/new_rule/metadata.json
  ℹ️  Upstream also has empty cwe

================================================================================
📊 SUMMARY
================================================================================
Field synced:              'cwe'
Total files checked:       270
Files with empty field:    180
✅ Successfully updated:   150
⚠️  Not found in upstream:  20
ℹ️  Upstream also empty:    10
❌ Errors:                 0
================================================================================
```

### Status Indicators

- **✅ Successfully updated** - Field was synced from upstream
- **⚠️ Not found in upstream** - Rule exists only in Datadog fork (custom rule, rule that was removed from Checkmarx)
- **ℹ️ Upstream also empty** - Upstream doesn't have this field either (new rule)
- **❌ Errors** - Technical errors (network, permissions, etc.)

## ⚠️ Important Notes

### 1. Datadog-Specific Rules

Some rules exist only in our Datadog fork:
- These will show as "⚠️ Not found in upstream"
- You'll need to manually populate fields for these rules

### 2. New Upstream Rules

Some rules in upstream may not have certain fields yet:
- These will show as "ℹ️ Upstream also empty"
- These are typically newer rules still in development
- Consider checking back after upstream updates

### 3. No Overwrites

The script only updates empty fields:
- If a field already has a value, it's skipped
- This prevents accidentally overwriting your customizations
- To force update, manually clear the field first, or modify the script

### 4. Batch Processing

For large syncs, consider processing in batches by platform:
```bash
# Better than syncing all 1,700+ files at once
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform cloudFormation
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform terraform
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform k8s
```

## 🐛 Troubleshooting

### Rate Limiting

If processing many files and hitting rate limits:
```bash
# Process in smaller batches with delays
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform cloudFormation
sleep 60
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform terraform
sleep 60
python3 sync_tools/sync_metadata_from_upstream.py --field cwe --platform k8s
```

To see all available fields, check any upstream metadata.json:
```bash
curl -s https://raw.githubusercontent.com/Checkmarx/kics/master/assets/queries/cloudFormation/aws/access_key_not_rotated_within_90_days/metadata.json | jq keys
```

## 📚 Additional Resources

- [Checkmarx KICS Repository](https://github.com/Checkmarx/kics)
- [CWE Database](https://cwe.mitre.org/)
- [KICS Documentation](https://docs.kics.io/)
- [Metadata Schema](https://github.com/Checkmarx/kics/blob/master/docs/schemas/metadata.json)
