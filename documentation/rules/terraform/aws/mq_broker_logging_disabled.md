---
title: "MQ broker logging disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/mq_broker_logging_disabled"
  id: "31245f98-a6a9-4182-9fc1-45482b9d030a"
  display_name: "MQ broker logging disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `31245f98-a6a9-4182-9fc1-45482b9d030a`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker)

### Description

 This check ensures that AWS MQ brokers have logging enabled in their configuration. ActiveMQ brokers should have both audit and general logging enabled, while RabbitMQ brokers only support general logging. Logging is essential for capturing critical security events and operational information, which aids in monitoring, troubleshooting, and forensic analysis. If logging is not enabled, malicious activity or configuration issues may go undetected, significantly increasing the risk of security breaches and data loss. Unaddressed, the lack of logging impedes compliance efforts and can hinder incident response due to an absence of necessary audit trails.


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

  logs {
      general = true
      audit = true
  }
}

resource "aws_mq_broker" "negative2" {
  broker_name = "rabbitmq-logging"
  engine_type = "RabbitMQ"

  logs {
      general = true
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_mq_broker" "positive1" {
  broker_name = "no-logging"
}

resource "aws_mq_broker" "positive2" {
  broker_name = "partial-logging"
  engine_type = "ActiveMQ"

  logs {
      general = true
  }
}

resource "aws_mq_broker" "positive3" {
  broker_name = "disabled-logging"
  engine_type = "ActiveMQ"

  logs {
      general = false
      audit = true
  }
}

resource "aws_mq_broker" "positive4" {
  broker_name = "rabbitmq-disabled-logging"
  engine_type = "RabbitMQ"

  logs {
      general = false
  }
}

```