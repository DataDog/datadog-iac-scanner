---
title: "GitHub repository set to public"
group_id: "Terraform / GitHub"
meta:
  name: "github/repository_set_to_public"
  id: "terraform-github-repository-set-to-public"
  display_name: "GitHub repository set to public"
  cloud_provider: "GitHub"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-github-repository-set-to-public{{< /copyable-code >}}

**Provider:** GitHub

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/providers/github/r/repository.html)

### Description

Repositories must be set to private. This requires the `visibility` attribute to be set to `private` and/or the `private` attribute to be `true`. If both are defined, `visibility` takes precedence over `private`.

## Compliant Code Examples
```terraform
resource "github_repository" "negative1" {
  name        = "example"
  description = "My awesome codebase"

  private = true

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "github_repository" "positive1" {
  name        = "example"
  description = "My awesome codebase"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}

resource "github_repository" "positive2" {
  name        = "example"
  description = "My awesome codebase"

  private = false

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}

resource "github_repository" "positive3" {
  name        = "example"
  description = "My awesome codebase"

  private = true
  visibility = "public"

  template {
    owner = "github"
    repository = "terraform-module-template"
  }
}

```