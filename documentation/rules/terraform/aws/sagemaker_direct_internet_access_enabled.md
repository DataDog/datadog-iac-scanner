---
title: "SageMaker notebook internet access enabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/sagemaker_direct_internet_access_enabled"
  id: "f3g4h5i6-j7k8-9lmn-0opq-12345abcdefg"
  display_name: "SageMaker notebook internet access enabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `f3g4h5i6-j7k8-9lmn-0opq-12345abcdefg`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sagemaker_notebook_instance#direct_internet_access)

### Description

 Amazon SageMaker notebook instances with direct internet access enabled create potential security vulnerabilities by allowing unauthorized outbound connections and possible data exfiltration channels. When enabled, malicious code or compromised notebooks can directly communicate with external servers, bypassing network security controls and potentially leaking sensitive information or intellectual property. To secure SageMaker notebook instances, you should explicitly disable direct internet access as shown in the following example:

```hcl
resource "aws_sagemaker_notebook_instance" "good_example" {
  name                   = "example-notebook"
  role_arn               = "arn:aws:iam::123456789012:role/SageMakerRole"
  direct_internet_access = "Disabled"
  instance_type          = "ml.t2.medium"
}
```

Avoid the insecure configuration that enables direct internet access:

```hcl
resource "aws_sagemaker_notebook_instance" "bad_example" {
  name                   = "example-notebook"
  role_arn               = "arn:aws:iam::123456789012:role/SageMakerRole"
  direct_internet_access = "Enabled" 
  instance_type          = "ml.t2.medium"
}
```


## Compliant Code Examples
```terraform
resource "aws_sagemaker_notebook_instance" "good_example" {
  name                   = "example-notebook"
  role_arn               = "arn:aws:iam::123456789012:role/SageMakerRole"
  direct_internet_access = "Disabled" # ✅ Direct internet access is correctly disabled
  instance_type          = "ml.t2.medium"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_sagemaker_notebook_instance" "bad_example" {
  name                   = "example-notebook"
  role_arn               = "arn:aws:iam::123456789012:role/SageMakerRole"
  direct_internet_access = "Enabled" # ❌ Direct internet access should be disabled
  instance_type          = "ml.t2.medium"
}

```