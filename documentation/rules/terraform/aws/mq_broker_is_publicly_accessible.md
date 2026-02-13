---
title: "MQ broker is publicly accessible"
group_id: "Terraform / AWS"
meta:
  name: "aws/mq_broker_is_publicly_accessible"
  id: "4eb5f791-c861-4afd-9f94-f2a6a3fe49cb"
  display_name: "MQ broker is publicly accessible"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `4eb5f791-c861-4afd-9f94-f2a6a3fe49cb`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker)

### Description

 This check verifies if AWS MQ brokers have the `publicly_accessible` attribute set to `true`, which makes them accessible from the internet. When an MQ broker is publicly accessible, it increases the attack surface and the risk of unauthorized access, potentially leading to data breaches or service disruption. To secure your MQ broker, omit the `publicly_accessible` attribute or explicitly set it to false, as shown below:

```
resource "aws_mq_broker" "secure_broker" {
  broker_name = "example"
  engine_type = "ActiveMQ"
  // Other configurations
  
  // Either omit this line completely or set to false
  publicly_accessible = false
}
```


## Compliant Code Examples
```terraform
resource "aws_mq_broker" "negative1" {
  broker_name = "example"

  configuration {
    id       = aws_mq_configuration.test.id
    revision = aws_mq_configuration.test.latest_revision
  }

  engine_type        = "ActiveMQ"
  engine_version     = "5.15.0"
  host_instance_type = "mq.t2.micro"
  security_groups    = [aws_security_group.test.id]

  user {
    username = "ExampleUser"
    password = "MindTheGap"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_mq_broker" "positive1" {
  broker_name = "example"

  configuration {
    id       = aws_mq_configuration.test.id
    revision = aws_mq_configuration.test.latest_revision
  }

  engine_type        = "ActiveMQ"
  engine_version     = "5.15.0"
  host_instance_type = "mq.t2.micro"
  security_groups    = [aws_security_group.test.id]

  user {
    username = "ExampleUser"
    password = "MindTheGap"
  }

  publicly_accessible = true
}
```