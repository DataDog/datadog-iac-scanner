# Terraform JSON Plan Generator

An AI-powered tool that automatically generates JSON plan files from Terraform configurations, with intelligent error fixing capabilities.

## Features

- **Recursive Processing**: Finds and processes all `.tf` files in a directory tree
- **AI-Powered Auto-Fix**: Uses Claude AI to automatically fix `terraform init` failures
- **Parallel Processing**: Process multiple files concurrently for faster execution
- **Smart Retry Logic**: Configurable retry attempts with AI-powered fixes between retries
- **Skip Existing**: Option to skip files that already have JSON plans
- **Comprehensive Logging**: Detailed progress tracking and error reporting
- **Dry Run Mode**: Preview what will be processed without making changes

## Prerequisites

1. **Terraform**: Must be installed and available in PATH
   ```bash
   terraform --version
   ```

2. **Python 3.7+**: Required for the script

3. **Anthropic API Key**: Required for AI-powered error fixing
   ```bash
   export ANTHROPIC_API_KEY="your-api-key-here"
   ```

   Or get your API key from: https://console.anthropic.com/

## Installation

1. Install Python dependencies:
   ```bash
   pip install anthropic
   ```

2. Make the script executable (optional):
   ```bash
   chmod +x generate_tf_plans.py
   ```

## Usage

### Basic Usage

Process all `.tf` files in a directory:
```bash
python generate_tf_plans.py /path/to/terraform/files
```

Process files in current directory:
```bash
python generate_tf_plans.py .
```

### Advanced Options

**Parallel Processing** (4 concurrent workers):
```bash
python generate_tf_plans.py /path/to/terraform --workers 4
```

**Skip Existing JSON Files**:
```bash
python generate_tf_plans.py /path/to/terraform --skip-existing
```

**Custom Retry Limit**:
```bash
python generate_tf_plans.py /path/to/terraform --max-retries 5
```

**Verbose Output**:
```bash
python generate_tf_plans.py /path/to/terraform --verbose
```

**Dry Run** (preview without making changes):
```bash
python generate_tf_plans.py /path/to/terraform --dry-run
```

**Provide API Key via CLI**:
```bash
python generate_tf_plans.py /path/to/terraform --api-key "your-api-key"
```

**Combined Options**:
```bash
python generate_tf_plans.py . --workers 4 --skip-existing --verbose
```

## How It Works

For each `.tf` file found:

1. **Copy to Temporary Directory**: Creates an isolated workspace
2. **Terraform Init**: Initializes the Terraform configuration
3. **AI Auto-Fix** (if init fails):
   - Sends the error and `.tf` content to Claude AI
   - Receives fixed Terraform code
   - Applies the fix and retries
   - Repeats up to `--max-retries` times
4. **Generate Plan**: Runs `terraform plan -out=tfplan`
5. **Convert to JSON**: Runs `terraform show -json tfplan`
6. **Save Result**: Writes `<basename>.json` to the original directory
7. **Cleanup**: Removes temporary files

## Output Format

The script generates JSON files in Terraform's standard plan format:

```
input.tf  →  input.json
```

Example output structure:
```json
{
  "format_version": "0.2",
  "terraform_version": "1.0.5",
  "planned_values": { ... },
  "resource_changes": [ ... ],
  "configuration": { ... }
}
```

## Exit Codes

- `0`: Success (all files processed successfully)
- `1`: Failure (one or more files failed to process)
- `130`: Interrupted by user (Ctrl+C)

## Example Output

```
2024-05-13 15:30:00 - INFO - Searching for .tf files in /path/to/terraform
2024-05-13 15:30:00 - INFO - Found 15 .tf files
2024-05-13 15:30:01 - INFO - Processing /path/to/terraform/test/negative1.tf
2024-05-13 15:30:05 - INFO - ✓ Successfully generated /path/to/terraform/test/negative1.json
2024-05-13 15:30:05 - INFO - Processing /path/to/terraform/test/positive1.tf
2024-05-13 15:30:10 - INFO - ✓ Successfully generated /path/to/terraform/test/positive1.json
...

============================================================
PROCESSING SUMMARY
============================================================
Total files:      15
✓ Success:        13
✗ Failed:         1
⊘ Skipped:        1
============================================================
```

## Troubleshooting

### "anthropic package not installed"
```bash
pip install anthropic
```

### "Anthropic API key not found"
Set the environment variable:
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

Or provide it via CLI:
```bash
python generate_tf_plans.py . --api-key "your-api-key-here"
```

### "terraform: command not found"
Install Terraform from: https://www.terraform.io/downloads

### AI fixes not working
- Ensure your API key is valid
- Check your Anthropic API quota/limits
- Review error messages with `--verbose` flag

### Timeout errors
Some complex Terraform configurations may take longer. The default timeout is 300 seconds (5 minutes) per command.

## Performance Tips

1. **Use parallel processing** for large directories:
   ```bash
   python generate_tf_plans.py . --workers 8
   ```

2. **Skip existing files** to avoid re-processing:
   ```bash
   python generate_tf_plans.py . --skip-existing
   ```

3. **Use dry-run first** to estimate scope:
   ```bash
   python generate_tf_plans.py . --dry-run
   ```

## Limitations

- Each `.tf` file is processed independently (no cross-file dependencies)
- Provider credentials are not configured (plans may be incomplete for resources requiring API calls)
- The script modifies `.tf` files in-place if AI fixes are applied
- Nested modules are not automatically resolved

## Security Considerations

- The script sends your Terraform code to Claude AI for error fixing
- Ensure you're comfortable sharing your infrastructure code with Anthropic's API
- Use `--dry-run` first to review what will be processed
- Consider using environment-specific configurations for sensitive infrastructure

## License

This script is part of the Datadog IaC Scanner project.
