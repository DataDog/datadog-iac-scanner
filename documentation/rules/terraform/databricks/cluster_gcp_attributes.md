---
title: "Check Databricks cluster GCP attribute best practices"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/cluster_gcp_attributes"
  id: "terraform-common-check-databricks-cluster-gcp-attribute-best-practices"
  display_name: "Check Databricks cluster GCP attribute best practices"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `terraform-common-check-databricks-cluster-gcp-attribute-best-practices`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.databricks.com/clusters/cluster-config-best-practices.html)

### Description

The rule flags `databricks_cluster` resources where `gcp_attributes.availability` is set to `PREEMPTIBLE_GCP`, which violates best practices. Clusters should use a non-preemptible availability setting.

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
  gcp_attributes {
    availability           = "PREEMPTIBLE_WITH_FALLBACK_GCP"
    zone_id                = "auto"
    first_on_demand        = 1
    spot_bid_price_percent = 100
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "databricks_cluster" "positive" {
  cluster_name            = "data"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 20
  autoscale {
    min_workers = 1
    max_workers = 50
  }
  gcp_attributes {
    availability           = "PREEMPTIBLE_GCP"
    zone_id                = "AUTO"
  }
}

```