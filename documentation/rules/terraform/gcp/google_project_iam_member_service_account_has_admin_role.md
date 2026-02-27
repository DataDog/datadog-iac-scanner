---
title: "Google project IAM member service account has admin role"
group_id: "Terraform / GCP"
meta:
  name: "gcp/google_project_iam_member_service_account_has_admin_role"
  id: "84d36481-fd63-48cb-838e-635c44806ec2"
  display_name: "Google project IAM member service account has admin role"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `84d36481-fd63-48cb-838e-635c44806ec2`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_member)

### Description

This query identifies when a service account is granted an administrative role in a Google Cloud project, which violates the principle of least privilege. Service accounts with administrative permissions such as `roles/iam.serviceAccountAdmin` can create and manage other service accounts, potentially leading to privilege escalation attacks and unauthorized access across your Google Cloud environment.

Instead of using administrative roles, assign more granular, limited roles that provide only the permissions required for the service account to function. For example:

```hcl
// Insecure configuration - service account with admin role
resource "google_project_iam_member" "insecure" {
  project = "your-project-id"
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:my-app@appspot.gserviceacccount.com"
}

// Secure configuration - service account with limited role
resource "google_project_iam_member" "secure" {
  project = "your-project-id"
  role    = "roles/editor"
  member  = "serviceAccount:my-app@appspot.gserviceacccount.com"
}
```

## Compliant Code Examples
```terraform
resource "google_project_iam_member" "negative1" {
  project = "your-project-id"
  role    = "roles/editor"
  members  = "user:jane@example.com"
}
```
## Non-Compliant Code Examples
```terraform
resource "google_project_iam_member" "positive1" {
  project = "your-project-id"
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:my-other-app@appspot.gserviceacccount.com"
}

resource "google_project_iam_member" "positive2" {
  project = "your-project-id"
  role    = "roles/iam.serviceAccountAdmin"
  members  = ["user:jane@example.com", "serviceAccount:my-other-app@appspot.gserviceacccount.com"]
}

```