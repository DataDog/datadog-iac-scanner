---
title: "SageMaker endpoint configuration encryption disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/sagemaker_endpoint_configuration_encryption_disabled"
  id: "58b35504-0287-4154-bf69-02c0573deab8"
  display_name: "SageMaker endpoint configuration encryption disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `58b35504-0287-4154-bf69-02c0573deab8`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sagemaker_endpoint_configuration#kms_key_arn)

### Description

 Amazon SageMaker endpoint configurations should have encryption enabled using a KMS key to protect sensitive data at rest. Without proper encryption, data stored within SageMaker endpoints may be vulnerable to unauthorized access if the underlying storage is compromised. This represents a significant security risk as machine learning endpoints often process and store sensitive information.

To address this vulnerability, specify the `kms_key_arn` attribute in your SageMaker endpoint configuration. For example, the secure implementation uses the following configuration, where kms_key_arn is specified to enable encryption:
```
resource "aws_sagemaker_endpoint_configuration" "example" {
  // other configuration
  kms_key_arn = "aws_kms_key.example.arn"
}
```
In contrast, the insecure version omits this critical encryption setting.


## Compliant Code Examples
```terraform
resource "aws_sagemaker_endpoint_configuration" "negative" {
  name = "my-endpoint-config"

  production_variants {
    variant_name           = "variant-1"
    model_name             = aws_sagemaker_model.m.name
    initial_instance_count = 1
    instance_type          = "ml.t2.medium"
  }

  tags = {
    Name = "foo"
  }

  kms_key_arn = "aws_kms_key.example.arn"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_sagemaker_endpoint_configuration" "positive" {
  name = "my-endpoint-config"

  production_variants {
    variant_name           = "variant-1"
    model_name             = aws_sagemaker_model.m.name
    initial_instance_count = 1
    instance_type          = "ml.t2.medium"
  }

  tags = {
    Name = "foo"
  }
}

```