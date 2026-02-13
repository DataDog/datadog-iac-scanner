---
title: "Beta - Databricks cluster or job with none or insecure permissions"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/databricks_permissions"
  id: "a4edb7e1-c0e0-4f7f-9d7c-d1b603e81ad5"
  display_name: "Beta - Databricks cluster or job with none or insecure permissions"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a4edb7e1-c0e0-4f7f-9d7c-d1b603e81ad5`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/databricks/databricks/latest/docs/resources/permissions)

### Description

 This rule verifies that each `databricks_job` and `databricks_cluster` resource has an associated `databricks_permissions` resource referencing it via `job_id` or `cluster_id`.

It also flags any `databricks_permissions` resource with `permission_level == "IS_OWNER"` that lacks an associated `service_principal_name`. Reported findings include `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue`.


## Compliant Code Examples
```terraform
resource "databricks_job" "negative3" {
  name                = "Featurization"
  max_concurrent_runs = 1

  new_cluster {
    num_workers   = 300
    spark_version = data.databricks_spark_version.latest.id
    node_type_id  = data.databricks_node_type.smallest.id
  }

  notebook_task {
    notebook_path = "/Production/MakeFeatures"
  }
}

resource "databricks_permissions" "negative3" {
  job_id = databricks_job.negative3.id

  access_control {
    service_principal_name = databricks_service_principal.aws_principal.application_id
    permission_level       = "IS_OWNER"
  }
}

```

```terraform
resource "databricks_cluster" "negative2" {
  cluster_name            = "Shared Autoscaling"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 60
  autoscale {
    min_workers = 1
    max_workers = 10
  }
}

resource "databricks_permissions" "negative2" {
  cluster_id = databricks_cluster.negative2.id

  access_control {
    group_name       = databricks_group.auto.display_name
    permission_level = "CAN_ATTACH_TO"
  }

  access_control {
    group_name       = databricks_group.eng.display_name
    permission_level = "CAN_RESTART"
  }

  access_control {
    group_name       = databricks_group.ds.display_name
    permission_level = "CAN_MANAGE"
  }
}

```

```terraform
resource "databricks_job" "negative1" {
  name                = "Featurization"
  max_concurrent_runs = 1

  new_cluster {
    num_workers   = 300
    spark_version = data.databricks_spark_version.latest.id
    node_type_id  = data.databricks_node_type.smallest.id
  }

  notebook_task {
    notebook_path = "/Production/MakeFeatures"
  }
}

resource "databricks_permissions" "negative1" {
  job_id = databricks_job.negative1.id

  access_control {
    group_name       = "users"
    permission_level = "CAN_VIEW"
  }

  access_control {
    group_name       = databricks_group.auto.display_name
    permission_level = "CAN_MANAGE_RUN"
  }

  access_control {
    group_name       = databricks_group.eng.display_name
    permission_level = "CAN_MANAGE"
  }

  access_control {
    service_principal_name = databricks_service_principal.aws_principal.application_id
    permission_level       = "IS_OWNER"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "databricks_cluster" "positive2" {
  cluster_name            = "Shared Autoscaling"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 60
  autoscale {
    min_workers = 1
    max_workers = 10
  }
}

resource "databricks_cluster" "positive2_error" {
  cluster_name            = "Shared Autoscaling"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 60
  autoscale {
    min_workers = 1
    max_workers = 10
  }
}

resource "databricks_permissions" "positive2" {
  cluster_id = databricks_cluster.positive2.id

  access_control {
    group_name       = databricks_group.auto.display_name
    permission_level = "CAN_ATTACH_TO"
  }

  access_control {
    group_name       = databricks_group.eng.display_name
    permission_level = "CAN_RESTART"
  }

  access_control {
    group_name       = databricks_group.ds.display_name
    permission_level = "CAN_MANAGE"
  }
}

```

```terraform
resource "databricks_job" "positive3" {
  name                = "Featurization"
  max_concurrent_runs = 1

  new_cluster {
    num_workers   = 300
    spark_version = data.databricks_spark_version.latest.id
    node_type_id  = data.databricks_node_type.smallest.id
  }

  notebook_task {
    notebook_path = "/Production/MakeFeatures"
  }
}

resource "databricks_permissions" "positive3" {
  job_id = databricks_job.positive3.id

  access_control {
    group_name       = "users"
    permission_level = "CAN_VIEW"
  }

  access_control {
    group_name       = databricks_group.auto.display_name
    permission_level = "CAN_MANAGE_RUN"
  }

  access_control {
    group_name       = databricks_group.eng.display_name
    permission_level = "CAN_MANAGE"
  }

  access_control {
    group_name       = databricks_group.eng.display_name
    permission_level = "IS_OWNER"
  }
}

```

```terraform
resource "databricks_job" "positive4" {
  name                = "Featurization"
  max_concurrent_runs = 1

  new_cluster {
    num_workers   = 300
    spark_version = data.databricks_spark_version.latest.id
    node_type_id  = data.databricks_node_type.smallest.id
  }

  notebook_task {
    notebook_path = "/Production/MakeFeatures"
  }
}

resource "databricks_permissions" "positive4" {
  job_id = databricks_job.positive4.id

  access_control {
    group_name       = databricks_group.eng.display_name
    permission_level = "IS_OWNER"
  }
}

```