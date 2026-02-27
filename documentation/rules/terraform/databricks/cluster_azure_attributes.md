---
title: "Beta - check Databricks cluster Azure attribute best practices"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/cluster_azure_attributes"
  id: "38028698-e663-4ef7-aa92-773fef0ca86f"
  display_name: "Beta - check Databricks cluster Azure attribute best practices"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `38028698-e663-4ef7-aa92-773fef0ca86f`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.databricks.com/clusters/cluster-config-best-practices.html)

### Description

One or more Azure attribute best practices are not followed for this Databricks cluster. The rule flags clusters when:

- `azure_attributes.availability` is set to `SPOT` or `SPOT_AZURE`,
- `azure_attributes.first_on_demand` is `0`, or
- `azure_attributes.first_on_demand` is missing.

These settings must ensure the use of at least one on-demand instance and avoid exclusive reliance on spot VMs.

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
  azure_attributes {
    availability           = "SPOT_WITH_FALLBACK_AZURE"
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
  azure_attributes {
    availability           = "SPOT_WITH_FALLBACK_AZURE"
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
  azure_attributes {
    availability           = "SPOT_WITH_FALLBACK_AZURE"
    zone_id                = "auto"
    spot_bid_price_percent = 100
  }
}

```

```terraform
resource "databricks_cluster" "positive1" {
  cluster_name            = "data"
  spark_version           = data.databricks_spark_version.latest.id
  node_type_id            = data.databricks_node_type.smallest.id
  autotermination_minutes = 20
  autoscale {
    min_workers = 1
    max_workers = 50
  }
  azure_attributes {
    availability           = "SPOT_AZURE"
    first_on_demand        = 1
    spot_bid_price_percent = 100
  }
}

```