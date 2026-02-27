---
title: "Service account with improper privileges"
group_id: "Terraform / GCP"
meta:
  name: "gcp/service_account_with_improper_privileges"
  id: "cefdad16-0dd5-4ac5-8ed2-a37502c78672"
  display_name: "Service account with improper privileges"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `cefdad16-0dd5-4ac5-8ed2-a37502c78672`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/data-sources/iam_policy#role)

### Description

Granting a service account excessive privileges such as `roles/admin`, `roles/editor`, `roles/owner`, or other write-level roles, can expose the environment to the risk of privilege escalation or unintended changes.  In Terraform, this misconfiguration appears when a binding like the following is used:

```
binding {
  role = "roles/editor"
  members = [
    "serviceAccount:jane@example.com",
  ]
}
```

aThis allows the service account broad permissions across resources. To follow the principle of least privilege, grant only the specific roles required. For example:

```
binding {
  role = "roles/apigee.runtimeAgent"
  members = [
    "user:jane@example.com",
  ]
}
```

Failing to restrict service account privileges can enable attackers or compromised services to make unauthorized changes, potentially leading to data exposure or resource compromise.

## Compliant Code Examples
```terraform
resource "google_project_iam_binding" "project5" {
  role = "roles/viewer"

  members = [
    "serviceAccount:jane@example.com",
  ]
}

data "google_iam_policy" "policy6" {
  binding {
    role = "roles/viewer"

    members = [
      "user:jane@example.com",
    ]
  }
}

```

```terraform
resource "google_project_iam_binding" "project3" {
  project = "your-project-id"
  role    = "roles/apigee.runtimeAgent"

  members = [
    "user:jane@example.com",
  ]

  condition {
    title       = "expires_after_2019_12_31"
    description = "Expiring at midnight of 2019-12-31"
    expression  = "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
  }
}

resource "google_project_iam_member" "project4" {
  project = "your-project-id"
  role    = "roles/apigee.runtimeAgent"
  member  = "user:jane@example.com"
}

```

```terraform
data "google_iam_policy" "policy5" {
  binding {
    role = "roles/apigee.runtimeAgent"

    members = [
      "user:jane@example.com",
    ]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_project_iam_binding" "project1" {
  project = "your-project-id"
  role    = "roles/container.admin"

  members = [
    "serviceAccount:jane@example.com",
  ]

  condition {
    title       = "expires_after_2019_12_31"
    description = "Expiring at midnight of 2019-12-31"
    expression  = "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
  }
}

resource "google_project_iam_member" "project2" {
  project = "your-project-id"
  role    = "roles/editor"
  member  = "serviceAccount:jane@example.com"
}

```

```terraform
data "google_iam_policy" "admin" {
  binding {
    role = "roles/compute.imageUser"

    members = [
      "serviceAccount:jane@example.com",
    ]
  }
  binding {
    role = "roles/owner"
    members = [
      "serviceAccount:john@example.com",
    ]
  }
}

```

```terraform
data "google_iam_policy" "admin" {
  binding {
    role = "roles/admin"
    members = [
      "serviceAccount:your-custom-sa@your-project.iam.gserviceaccount.com",
    ]
  }
  binding {
    role = "roles/editor"
    members = [
      "serviceAccount:alice@gmail.com",
    ]
  }
}

```