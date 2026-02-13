---
title: "Batch job definition with privileged container properties"
group_id: "Terraform / AWS"
meta:
  name: "aws/batch_job_definition_with_privileged_container_properties"
  id: "66cd88ac-9ddf-424a-b77e-e55e17630bee"
  display_name: "Batch job definition with privileged container properties"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `66cd88ac-9ddf-424a-b77e-e55e17630bee`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/batch_job_definition)

### Description

 AWS Batch Job Definitions with privileged container properties grant elevated permissions to the container, essentially providing it with root-level access to the host machine. This configuration creates a significant security risk as containers can access host resources and potentially escape container isolation, leading to unauthorized access or system compromise. Instead, containers should run with minimum required privileges according to the principle of least privilege. To secure your configuration, either explicitly set the privileged property to `false` or omit it entirely, as shown below:

```terraform
container_properties = <<CONTAINER_PROPERTIES
{
    "command": ["ls", "-la"],
    "image": "busybox",
    "memory": 1024,
    "vcpus": 1,
    "privileged": false,
    // ... other properties
}
CONTAINER_PROPERTIES
```


## Compliant Code Examples
```terraform
resource "aws_batch_job_definition" "negative1" {
  name = "tf_test_batch_job_definition"
  type = "container"

  container_properties = <<CONTAINER_PROPERTIES
{
    "command": ["ls", "-la"],
    "image": "busybox",
    "memory": 1024,
    "vcpus": 1,
    "privileged": false,
    "volumes": [
      {
        "host": {
          "sourcePath": "/tmp"
        },
        "name": "tmp"
      }
    ],
    "environment": [
        {"name": "VARNAME", "value": "VARVAL"}
    ],
    "mountPoints": [
        {
          "sourceVolume": "tmp",
          "containerPath": "/tmp",
          "readOnly": false
        }
    ],
    "ulimits": [
      {
        "hardLimit": 1024,
        "name": "nofile",
        "softLimit": 1024
      }
    ]
}
CONTAINER_PROPERTIES
}

resource "aws_batch_job_definition" "negative2" {
  name = "tf_test_batch_job_definition2"
  type = "container"

  container_properties = <<CONTAINER_PROPERTIES
{
    "command": ["ls", "-la"],
    "image": "busybox",
    "memory": 1024,
    "vcpus": 1,
    "volumes": [
      {
        "host": {
          "sourcePath": "/tmp"
        },
        "name": "tmp"
      }
    ],
    "environment": [
        {"name": "VARNAME", "value": "VARVAL"}
    ],
    "mountPoints": [
        {
          "sourceVolume": "tmp",
          "containerPath": "/tmp",
          "readOnly": false
        }
    ],
    "ulimits": [
      {
        "hardLimit": 1024,
        "name": "nofile",
        "softLimit": 1024
      }
    ]
}
CONTAINER_PROPERTIES
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_batch_job_definition" "positive1" {
  name = "tf_test_batch_job_definition"
  type = "container"

  container_properties = <<CONTAINER_PROPERTIES
{
    "command": ["ls", "-la"],
    "image": "busybox",
    "memory": 1024,
    "vcpus": 1,
    "privileged": true,
    "volumes": [
      {
        "host": {
          "sourcePath": "/tmp"
        },
        "name": "tmp"
      }
    ],
    "environment": [
        {"name": "VARNAME", "value": "VARVAL"}
    ],
    "mountPoints": [
        {
          "sourceVolume": "tmp",
          "containerPath": "/tmp",
          "readOnly": false
        }
    ],
    "ulimits": [
      {
        "hardLimit": 1024,
        "name": "nofile",
        "softLimit": 1024
      }
    ]
}
CONTAINER_PROPERTIES
}

```