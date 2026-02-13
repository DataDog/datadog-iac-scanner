---
title: "IAM audit not properly configured"
group_id: "Terraform / GCP"
meta:
  name: "gcp/iam_audit_not_properly_configured"
  id: "89fe890f-b480-460c-8b6b-7d8b1468adb4"
  display_name: "IAM audit not properly configured"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `89fe890f-b480-460c-8b6b-7d8b1468adb4`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_audit_config)

### Description

A defective audit logging configuration in Terraform, as defined by the `google_project_iam_audit_config` resource, can lead to incomplete or incorrect logging of critical activities within your cloud environment. For example, omitting required `log_type` values or specifying exempted members, as shown below, allows certain user actions to go unrecorded, potentially bypassing audit trails and hampering incident investigations:

```
resource "google_project_iam_audit_config" "example" {
  project = "your-project-id"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
    exempted_members = ["user:joebloggs@hashicorp.com"]
  }
}
```

Without comprehensive audit logs, organizations may be unable to detect or investigate unauthorized access or changes, increasing the risk of undetected misuse or data breaches. A secure configuration should ensure that all required log types (such as `ADMIN_READ` and `DATA_READ`) are enabled and that no users or accounts are unnecessarily exempted from logging.

## Compliant Code Examples
```terraform
resource "google_project_iam_audit_config" "negative1" {
  project = "your-project-id"
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "google_project_iam_audit_config" "positive1" {
  project = "your-project-id"
  service = "some_specific_service"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
    exempted_members = [
      "user:joebloggs@hashicorp.com"
    ]
  }
}

resource "google_project_iam_audit_config" "positive2" {
  project = "your-project-id"
  service = "allServices"
  audit_log_config {
    log_type = "INVALID_TYPE"
  }
  audit_log_config {
    log_type = "DATA_READ"
    exempted_members = [
        "user:joebloggs@hashicorp.com"
    ]
  }
}
```