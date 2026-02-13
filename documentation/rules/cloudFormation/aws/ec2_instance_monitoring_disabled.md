---
title: "EC2 instance monitoring disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_instance_monitoring_disabled"
  id: "0264093f-6791-4475-af34-4b8102dcbcd0"
  display_name: "EC2 instance monitoring disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `0264093f-6791-4475-af34-4b8102dcbcd0`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-monitoring)

### Description

 EC2 instances should have detailed (1-minute) monitoring enabled to improve detection and response to performance and security incidents and to provide higher-resolution metrics for investigations and alerting. In CloudFormation, the `AWS::EC2::Instance` resource must include the `Monitoring` property set to `true`. Resources missing `Monitoring` or with `Monitoring` set to `false` will be flagged.

```yaml
MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    InstanceType: t3.micro
    ImageId: ami-0123456789abcdef0
    Monitoring: true
```


## Compliant Code Examples
```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345678
      InstanceType: t2.micro
      Monitoring: true

```
## Non-Compliant Code Examples
```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345678
      InstanceType: t2.micro

```

```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-12345678
      InstanceType: t2.micro
      Monitoring: false

```