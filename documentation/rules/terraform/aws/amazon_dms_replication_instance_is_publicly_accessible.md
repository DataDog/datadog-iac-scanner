---
title: "Amazon DMS replication instance is publicly accessible"
group_id: "Terraform / AWS"
meta:
  name: "aws/amazon_dms_replication_instance_is_publicly_accessible"
  id: "030d3b18-1821-45b4-9e08-50efbe7becbb"
  display_name: "Amazon DMS replication instance is publicly accessible"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `030d3b18-1821-45b4-9e08-50efbe7becbb`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dms_replication_instance)

### Description

Amazon DMS Replication Instances with `publicly_accessible` set to `true` expose their endpoints to the public internet, significantly increasing the attack surface and potential for unauthorized access to sensitive migration data. This configuration can lead to data breaches, as DMS instances may contain credentials, connection strings, and other sensitive information needed for database migration. To mitigate this risk, always set `publicly_accessible` to false (or omit it since false is the default) and use private networking with proper security groups as shown in the negative example: `resource "aws_dms_replication_instance" "test" { ... }` where the publicly_accessible attribute is not specified.

## Compliant Code Examples
```terraform
resource "aws_dms_replication_instance" "test" {
  allocated_storage            = 20
  apply_immediately            = true
  auto_minor_version_upgrade   = true
  availability_zone            = "us-west-2c"
  engine_version               = "3.1.4"
  kms_key_arn                  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  multi_az                     = false
  publicly_accessible          = false
  preferred_maintenance_window = "sun:10:30-sun:14:30"
  replication_instance_class   = "dms.t2.micro"
  replication_instance_id      = "test-dms-replication-instance-tf"
  replication_subnet_group_id  = aws_dms_replication_subnet_group.test-dms-replication-subnet-group-tf.id

  vpc_security_group_ids = [
    "sg-12345678",
  ]

  depends_on = [
    aws_iam_role_policy_attachment.dms-access-for-endpoint-AmazonDMSRedshiftS3Role,
    aws_iam_role_policy_attachment.dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole,
    aws_iam_role_policy_attachment.dms-vpc-role-AmazonDMSVPCManagementRole
  ]
}
```

```terraform
resource "aws_dms_replication_instance" "test" {
  allocated_storage            = 20
  apply_immediately            = true
  auto_minor_version_upgrade   = true
  availability_zone            = "us-west-2c"
  engine_version               = "3.1.4"
  kms_key_arn                  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  multi_az                     = false
  preferred_maintenance_window = "sun:10:30-sun:14:30"
  replication_instance_class   = "dms.t2.micro"
  replication_instance_id      = "test-dms-replication-instance-tf"
  replication_subnet_group_id  = aws_dms_replication_subnet_group.test-dms-replication-subnet-group-tf.id

  vpc_security_group_ids = [
    "sg-12345678",
  ]

  depends_on = [
    aws_iam_role_policy_attachment.dms-access-for-endpoint-AmazonDMSRedshiftS3Role,
    aws_iam_role_policy_attachment.dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole,
    aws_iam_role_policy_attachment.dms-vpc-role-AmazonDMSVPCManagementRole
  ]
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_dms_replication_instance" "test" {
  allocated_storage            = 20
  apply_immediately            = true
  auto_minor_version_upgrade   = true
  availability_zone            = "us-west-2c"
  engine_version               = "3.1.4"
  kms_key_arn                  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  multi_az                     = false
  preferred_maintenance_window = "sun:10:30-sun:14:30"
  publicly_accessible          = true
  replication_instance_class   = "dms.t2.micro"
  replication_instance_id      = "test-dms-replication-instance-tf"
  replication_subnet_group_id  = aws_dms_replication_subnet_group.test-dms-replication-subnet-group-tf.id

  vpc_security_group_ids = [
    "sg-12345678",
  ]

  depends_on = [
    aws_iam_role_policy_attachment.dms-access-for-endpoint-AmazonDMSRedshiftS3Role,
    aws_iam_role_policy_attachment.dms-cloudwatch-logs-role-AmazonDMSCloudWatchLogsRole,
    aws_iam_role_policy_attachment.dms-vpc-role-AmazonDMSVPCManagementRole
  ]
}
```