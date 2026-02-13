---
title: "MSK broker is publicly accessible"
group_id: "Terraform / AWS"
meta:
  name: "aws/msk_broker_is_publicly_accessible"
  id: "54378d69-dd7c-4b08-a43e-80d563396857"
  display_name: "MSK broker is publicly accessible"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `54378d69-dd7c-4b08-a43e-80d563396857`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#public_access)

### Description

 Amazon MSK (Managed Streaming for Kafka) clusters with public accessibility enabled allow connections from the internet, which significantly expands the attack surface and increases the risk of unauthorized access to sensitive data streams. When MSK brokers are publicly accessible, they can be targeted by malicious actors who may attempt to intercept data, perform denial-of-service attacks, or exploit vulnerabilities to gain deeper access to your infrastructure. 

To secure your MSK cluster, configure the `public_access` type as `DISABLED` rather than `SERVICE_PROVIDED_EIPS`, as shown below:

```hcl
broker_node_group_info {
  connectivity_info {
    public_access {
      type = "DISABLED"
    }
  }
}
```

For additional security, implement network ACLs, security groups, and private VPC endpoints to control access to your MSK resources.


## Compliant Code Examples
```terraform
resource "aws_msk_cluster" "negative2" {
  cluster_name           = "example"
  kafka_version          = "2.7.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type = "kafka.m5.4xlarge"
    client_subnets = [
      aws_subnet.subnet_az1.id,
      aws_subnet.subnet_az2.id,
      aws_subnet.subnet_az3.id,
    ]
    storage_info {
      ebs_storage_info {
        provisioned_throughput {
          enabled           = true
          volume_throughput = 250
        }
        volume_size = 1000
      }
    }
    security_groups = [aws_security_group.sg.id]
  }
}

```

```terraform
resource "aws_msk_cluster" "negative1" {
  cluster_name           = "example"
  kafka_version          = "2.7.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    connectivity_info {
      public_access {
        type = "DISABLED"
      }
    }
    instance_type = "kafka.m5.4xlarge"
    client_subnets = [
      aws_subnet.subnet_az1.id,
      aws_subnet.subnet_az2.id,
      aws_subnet.subnet_az3.id,
    ]
    storage_info {
      ebs_storage_info {
        provisioned_throughput {
          enabled           = true
          volume_throughput = 250
        }
        volume_size = 1000
      }
    }
    security_groups = [aws_security_group.sg.id]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_msk_cluster" "positive1" {
  cluster_name           = "example"
  kafka_version          = "2.7.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    connectivity_info {
      public_access {
        type = "SERVICE_PROVIDED_EIPS"
      }
    }
    instance_type = "kafka.m5.4xlarge"
    client_subnets = [
      aws_subnet.subnet_az1.id,
      aws_subnet.subnet_az2.id,
      aws_subnet.subnet_az3.id,
    ]
    storage_info {
      ebs_storage_info {
        provisioned_throughput {
          enabled           = true
          volume_throughput = 250
        }
        volume_size = 1000
      }
    }
    security_groups = [aws_security_group.sg.id]
  }
}

```