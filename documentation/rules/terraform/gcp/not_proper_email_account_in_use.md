---
title: "Not proper email account in use"
group_id: "Terraform / GCP"
meta:
  name: "gcp/not_proper_email_account_in_use"
  id: "9356962e-4a4f-4d06-ac59-dc8008775eaa"
  display_name: "Not proper email account in use"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9356962e-4a4f-4d06-ac59-dc8008775eaa`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_binding)

### Description

 Using personal Gmail accounts instead of corporate credentials in IAM bindings introduces a security risk by granting project access to external, non-managed identities that are not subject to company oversight, monitoring, or access controls. For example:

```
resource "google_project_iam_binding" "positive1" {
  project = "your-project-id"
  role    = "roles/editor"

  members = [
    "user:jane@gmail.com",
  ]
}
```

If left unaddressed, this vulnerability can enable unauthorized users to retain access even after leaving the organization or becoming compromised, significantly increasing the risk of data leaks and unauthorized modifications.

Using organization-managed accounts, as in the following configuration, ensures better control and the ability to revoke access when necessary:

```
resource "google_project_iam_binding" "negative1" {
  project = "your-project-id"
  role    = "roles/editor"

  members = [
    "user:jane@example.com",
  ]
}
```


## Compliant Code Examples
```terraform
resource "google_project_iam_binding" "negative1" {
  project = "your-project-id"
  role    = "roles/editor"

  members = [
    "user:jane@example.com",
  ]
}
```
## Non-Compliant Code Examples
```terraform
resource "google_project_iam_binding" "positive1" {
  project = "your-project-id"
  role    = "roles/editor"

  members = [
    "user:jane@gmail.com",
  ]
}
```