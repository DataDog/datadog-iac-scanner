---
title: "User with IAM role"
group_id: "Terraform / GCP"
meta:
  name: "gcp/user_with_iam_role"
  id: "704fcc44-a58f-4af5-82e2-93f2a58ef918"
  display_name: "User with IAM role"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `704fcc44-a58f-4af5-82e2-93f2a58ef918`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/data-sources/iam_policy#role)

### Description

Assigning an IAM role directly to a user rather than to a group is considered a misconfiguration, as it reduces flexibility and scalability in managing permissions. This practice can also lead to security risks; if the user leaves the organization or changes roles, their individual permissions may be overlooked and not revoked, resulting in excessive access. Using a group-based assignment, as shown below, ensures a more centralized and manageable permission structure:

```
data "google_iam_policy" "secure" {
  binding {
    role = "roles/apigee.runtimeAgent"

    members = [
      "group:jane@example.com",
    ]
  }
}
```

## Compliant Code Examples
```terraform
data "google_iam_policy" "negative" {
  binding {
    role = "roles/apigee.runtimeAgent"

    members = [
      "group:jane@example.com",
    ]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_project_iam_binding" "positive2" {
  project = "your-project-id"
  role    = "roles/container.admin"

  members = [
    "user:jane@example.com",
  ]

  condition {
    title       = "expires_after_2019_12_31"
    description = "Expiring at midnight of 2019-12-31"
    expression  = "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
  }
}

resource "google_project_iam_member" "positive3" {
  project = "your-project-id"
  role    = "roles/editor"
  member  = "user:jane@example.com"
}

```

```terraform
data "google_iam_policy" "positive" {
  binding {
    role = "roles/apigee.runtimeAgent"

    members = [
      "user:jane@example.com",
    ]
  }
}

```