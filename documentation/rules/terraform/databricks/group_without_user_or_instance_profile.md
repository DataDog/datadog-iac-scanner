---
title: "Beta - Databricks group without user or instance profile"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/group_without_user_or_instance_profile"
  id: "23c3067a-8cc9-480c-b645-7c1e0ad4bf60"
  display_name: "Beta - Databricks group without user or instance profile"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `23c3067a-8cc9-480c-b645-7c1e0ad4bf60`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/databricks/databricks/latest/docs/resources/group)

### Description

 Each `databricks_group` must be associated with at least one user or one instance profile. This rule checks for:

- A `databricks_group_member` with a non-empty member_id, or
- A `databricks_group_instance_profile` with a non-empty `instance_profile_id`

If neither is found referencing the group's `group_id`, the `databricks_group` is flagged.


## Compliant Code Examples
```terraform
resource "databricks_instance_profile" "negative2_instance_profile" {
  instance_profile_arn = "my_instance_profile_arn"
}

resource "databricks_group" "negative2_group" {
  display_name = "my_group_name"
}

resource "databricks_group_instance_profile" "negative2_group_instance_profile" {
  group_id            = databricks_group.negative2_group.id
  instance_profile_id = databricks_instance_profile.negative2_instance_profile.id
}

```

```terraform
resource "databricks_group" "negative1_group" {
  display_name               = "Some Group"
  allow_cluster_create       = true
  allow_instance_pool_create = true
}

resource "databricks_user" "negative1_user" {
  user_name = "someone@example.com"
}

resource "databricks_group_member" "negative1_member" {
  group_id  = databricks_group.negative1_group.id
  member_id = databricks_user.negative1_user.id
}

```
## Non-Compliant Code Examples
```terraform
resource "databricks_instance_profile" "positive_instance_profile" {
  instance_profile_arn = "my_instance_profile_arn"
}

resource "databricks_group" "positive_group" {
  display_name = "my_group_name"
}

resource "databricks_group_instance_profile" "my_group_instance_profile" {
  group_id            = databricks_group.positive_group.id
  instance_profile_id = databricks_instance_profile.positive_instance_profile.id
}

resource "databricks_group" "positive_group2" {
  display_name = "my_group_name"
}

```

```terraform
resource "databricks_group" "positive_group" {
  display_name               = "Some Group"
  allow_cluster_create       = true
  allow_instance_pool_create = true
}

resource "databricks_user" "positive_user" {
  user_name = "someone@example.com"
}

resource "databricks_group_member" "positive_member" {
  group_id  = databricks_group.positive_group.id
  member_id = databricks_user.positive_user.id
}

resource "databricks_group" "positive_group_2" {
  display_name               = "Some Group"
  allow_cluster_create       = true
  allow_instance_pool_create = true
}

```