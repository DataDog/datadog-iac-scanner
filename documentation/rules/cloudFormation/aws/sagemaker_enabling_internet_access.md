---
title: "SageMaker enabling internet access"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/sagemaker_enabling_internet_access"
  id: "88d55d94-315d-4564-beee-d2d725feab11"
  display_name: "SageMaker enabling internet access"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `88d55d94-315d-4564-beee-d2d725feab11`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html#sagemaker-condition-nbi-lockdown)

### Description

SageMaker notebook instances must have direct internet access disabled to prevent notebooks from initiating outbound connections. Outbound access can be used to exfiltrate sensitive data or download and execute malicious code.

In CloudFormation, `AWS::SageMaker::NotebookInstance` resources must include `Properties.DirectInternetAccess` set to `Disabled`. Resources that omit `DirectInternetAccess`, or set it to any other value, will be flagged.

```yaml
MyNotebook:
  Type: AWS::SageMaker::NotebookInstance
  Properties:
    NotebookInstanceName: my-notebook
    InstanceType: ml.t2.medium
    RoleArn: arn:aws:iam::123456789012:role/SageMakerExecutionRole
    DirectInternetAccess: Disabled
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Internet access and root access for Creating Notebook Instances"
Resources:
  Notebook:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      DirectInternetAccess: "Disabled"
      InstanceType: "ml.c4.2xlarge"
      RoleArn: "role"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Internet access and root access for Creating Notebook Instances",
  "Resources": {
    "Notebook": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "Properties": {
        "DirectInternetAccess": "Disabled",
        "InstanceType": "ml.c4.2xlarge",
        "RoleArn": "role"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Notebook": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "Properties": {
        "InstanceType": "ml.c4.2xlarge",
        "RoleArn": "role",
        "DirectInternetAccess": "Enabled"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Internet access and root access for Creating Notebook Instances"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Internet access and root access for Creating Notebook Instances"
Resources:
  Notebook:
    Type: AWS::SageMaker::NotebookInstance
    Properties:
      DirectInternetAccess: "Enabled"
      InstanceType: "ml.c4.2xlarge"
      RoleArn: "role"

```