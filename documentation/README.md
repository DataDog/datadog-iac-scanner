# 📄 Rule Documentation Generator

This script generates Markdown documentation files for the DD kics infrastructure-as-code rules, based on `metadata.json` files and Terraform test cases. It also produces two summary files: a `list.json` file describing all documented rules, and a `frontmatter.yaml` file for use with DD Documentation website.

## 🚀 Features

* Automatically generates `.md` files for each rule, organized by cloud provider and resource type.
* Includes code examples (compliant and non-compliant) from test cases.
* Creates structured `list.json` and `frontmatter.yaml` for integration with documentation tooling.
* Handles nested directory structures for multiple providers and resource types.

---

## 📁 Structure of a Documentation File

Each Markdown documentation file includes:

* **YAML Frontmatter:** Metadata for static site generators
* **Metadata Section:** Basic rule information like ID, severity, category, etc.
* **Description Section:** Human-readable explanation of the rule
* **Links Section:** Optional link to an external reference
* **Compliant & Non-Compliant Code Examples:** Taken from Terraform test files (`positive*.tf` and `negative*.tf`)

---

## 🧩 Directory Layout

Expected directory structure:

```
input_dir/
└── <resource_type>/
    └── <provider>/
        └── <rule_name>/
            ├── metadata.json
            └── test/
                ├── positive_example1.tf
                ├── negative_example1.tf
                └── ...
```

---

## 🛠️ Usage

Run the script using:

```bash
python3 local_gen.py <input_dir> \
  --resources-json resources.json \
  --output-dir docs/rules \
  --list-json docs/list.json \
  --frontmatter-yaml docs/frontmatter.yaml \
  --max-examples 3
```

### Arguments

* `input_dir`: Directory with rule files
* `--resources-json`: JSON file mapping `resource_type` → list of `providers`
* `--output-dir`: Where generated markdown files will go (default: `rules`)
* `--list-json`: Output path for `list.json` summary (default: `list.json`)
* `--frontmatter-yaml`: Output path for `frontmatter.yaml` (default: `frontmatter.yaml`)
* `--max-examples`: Maximum number of code examples to include per rule (default: 3)

---

## 🧪 resources.json Format

```json
{
  "ansible": ["gcp"],
  "terraform": ["aws"],
  "default": ["aws", "gcp", "azure"]
}
```

If a `resource_type` has no providers listed, it falls back to the `"default"` list.

---

## 📤 Output Files

### Markdown Files

Located in `--output-dir`, each rule will generate:

```
<output_dir>/<resource_type>/<provider>/<rule_name>.md
```

### list.json

Nested list of all providers and rules, suitable for menus or documentation trees.

### frontmatter.yaml

YAML structure suitable for static site frontmatter integration.

---

## 🧹 Cleanup

The script clears the existing `--output-dir` on each run to ensure a clean rebuild of documentation.

---

## ❗Notes

* Escapes any triple backticks in example code to prevent Markdown breakage.
* Gracefully handles missing or malformed `metadata.json` files.
* Warns if any expected directories are missing.

---

## ✅ Example

To generate documentation for Terraform AWS and GCP rules:

```bash
uv run script.py ./rules-input \
  --resources-json ./resources.json \
  --output-dir ./docs/rules \
  --list-json ./docs/list.json \
  --frontmatter-yaml ./docs/frontmatter.yaml
```