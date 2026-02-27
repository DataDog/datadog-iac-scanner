---
title: "Workspaces workspace volume not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/workspaces_workspace_volume_not_encrypted"
  id: "b9033580-6886-401a-8631-5f19f5bb24c7"
  display_name: "Workspaces workspace volume not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `b9033580-6886-401a-8631-5f19f5bb24c7`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace#root_volume_encryption_enabled)

### Description

AWS Workspaces provides virtual desktop infrastructure in the cloud with both root and user volumes that should be encrypted to protect sensitive data from unauthorized access. When these volumes are not encrypted, workspace data including user files, system configurations, and application data are vulnerable to exposure if the storage media is compromised or improperly decommissioned. To properly secure your workspaces, the `root_volume_encryption_enabled` and `user_volume_encryption_enabled` attributes must be set to `true`, as shown in the following example:

```terraform
resource "aws_workspaces_workspace" "example" {
  // Other configuration...
  root_volume_encryption_enabled = true
  user_volume_encryption_enabled = true
  volume_encryption_key          = "alias/aws/workspaces"
}
```

## Compliant Code Examples
```terraform
resource "aws_workspaces_workspace" "example" {
  directory_id = aws_workspaces_directory.example.id
  bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
  user_name    = "john.doe"

  root_volume_encryption_enabled = true
  user_volume_encryption_enabled = true
  volume_encryption_key          = "alias/aws/workspaces"

  workspace_properties {
    compute_type_name                         = "VALUE"
    user_volume_size_gib                      = 10
    root_volume_size_gib                      = 80
    running_mode                              = "AUTO_STOP"
    running_mode_auto_stop_timeout_in_minutes = 60
  }

  tags = {
    Department = "IT"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_workspaces_workspace" "example_2" {
  directory_id = aws_workspaces_directory.example.id
  bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
  user_name    = "john.doe"

  user_volume_encryption_enabled = true
  volume_encryption_key          = "alias/aws/workspaces"

  workspace_properties {
    compute_type_name                         = "VALUE"
    user_volume_size_gib                      = 10
    root_volume_size_gib                      = 80
    running_mode                              = "AUTO_STOP"
    running_mode_auto_stop_timeout_in_minutes = 60
  }

  tags = {
    Department = "IT"
  }
}

```

```terraform
resource "aws_workspaces_workspace" "example_3" {
  directory_id = aws_workspaces_directory.example.id
  bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
  user_name    = "john.doe"

  volume_encryption_key          = "alias/aws/workspaces"

  workspace_properties {
    compute_type_name                         = "VALUE"
    user_volume_size_gib                      = 10
    root_volume_size_gib                      = 80
    running_mode                              = "AUTO_STOP"
    running_mode_auto_stop_timeout_in_minutes = 60
  }

  tags = {
    Department = "IT"
  }
}

```

```terraform
resource "aws_workspaces_workspace" "example_4" {
  directory_id = aws_workspaces_directory.example.id
  bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
  user_name    = "john.doe"

  root_volume_encryption_enabled = false
  user_volume_encryption_enabled = false
  volume_encryption_key          = "alias/aws/workspaces"

  workspace_properties {
    compute_type_name                         = "VALUE"
    user_volume_size_gib                      = 10
    root_volume_size_gib                      = 80
    running_mode                              = "AUTO_STOP"
    running_mode_auto_stop_timeout_in_minutes = 60
  }

  tags = {
    Department = "IT"
  }
}

```