---
title: "Beta - check Databricks cluster AWS attribute best practices"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/cluster_aws_attributes"
  id: "b0749c53-e3ff-4d09-bbe4-dca94e2e7a38"
  display_name: "Beta - check Databricks cluster AWS attribute best practices"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `b0749c53-e3ff-4d09-bbe4-dca94e2e7a38`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.databricks.com/clusters/cluster-config-best-practices.html)

### Description

 One or more AWS attribute best practices are not followed for this Databricks cluster.

The rule flags `databricks_cluster` resources when:

- `aws_attributes.availability` is set to `SPOT`
- `aws_attributes.first_on_demand` is missing or set to `0`
- `aws_attributes.zone_id` is not equal to `auto`

Each finding includes `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue`.


## Compliant Code Examples
```terraform
resource "databricks_cluster" "negative" {
  cluster_name            = "Shared Autoscaling"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 20
  autoscale {
    min_workers = 1
    max_workers = 50
  }
  aws_attributes {
    availability           = "SPOT_WITH_FALLBACK"
    zone_id                = "auto"
    first_on_demand        = 1
    spot_bid_price_percent = 100
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "databricks_cluster" "positive2" {
  cluster_name            = "data"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 20
  autoscale {
    min_workers = 1
    max_workers = 50
  }
  aws_attributes {
    availability           = "SPOT_WITH_FALLBACK"
    zone_id                = "auto"
    first_on_demand        = 0
    spot_bid_price_percent = 100
  }
}

```

```terraform
resource "databricks_cluster" "positive3" {
  cluster_name            = "data"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 20
  autoscale {
    min_workers = 1
    max_workers = 50
  }
  aws_attributes {
    availability           = "SPOT_WITH_FALLBACK"
    zone_id                = "auto"
    spot_bid_price_percent = 100
  }
}

```

```terraform
resource "databricks_cluster" "positive4" {
  cluster_name            = "data"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 20
  autoscale {
    min_workers = 1
    max_workers = 50
  }
  aws_attributes {
    availability           = "SPOT_WITH_FALLBACK"
    zone_id                = "us-west-2a"
    first_on_demand        = 1
    spot_bid_price_percent = 100
  }
}

```