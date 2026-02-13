---
title: "SageMaker notebook instance without KMS"
group_id: "Terraform / AWS"
meta:
  name: "aws/sagemaker_notebook_instance_without_kms"
  id: "f3674e0c-f6be-43fa-b71c-bf346d1aed99"
  display_name: "SageMaker notebook instance without KMS"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `f3674e0c-f6be-43fa-b71c-bf346d1aed99`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sagemaker_notebook_instance#kms_key_id)

### Description

 AWS SageMaker notebook instances should be configured with a KMS key for encryption at rest to protect sensitive data and machine learning artifacts. Without proper encryption, confidential information stored in these notebooks may be exposed to unauthorized access, potentially leading to data breaches and compliance violations. To secure your SageMaker notebook instance, specify the `kms_key_id` attribute in your Terraform configuration, as shown below:

```
resource "aws_sagemaker_notebook_instance" "ni" {
  name          = "my-notebook-instance"
  role_arn      = aws_iam_role.role.arn
  instance_type = "ml.t2.medium"
  kms_key_id    = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
```


## Compliant Code Examples
```terraform
resource "aws_sagemaker_notebook_instance" "ni" {
  name          = "my-notebook-instance"
  role_arn      = aws_iam_role.role.arn
  instance_type = "ml.t2.medium"
  kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

  tags = {
    Name = "foo"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_sagemaker_notebook_instance" "ni" {
  name          = "my-notebook-instance"
  role_arn      = aws_iam_role.role.arn
  instance_type = "ml.t2.medium"

  tags = {
    Name = "foo"
  }
}

```