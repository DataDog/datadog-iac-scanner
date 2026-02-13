---
title: "Hardcoded AWS access key"
group_id: "Terraform / AWS"
meta:
  name: "aws/hardcoded_aws_access_key"
  id: "d7b9d850-3e06-4a75-852f-c46c2e92240b"
  display_name: "Hardcoded AWS access key"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `d7b9d850-3e06-4a75-852f-c46c2e92240b`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance)

### Description

 Hardcoding AWS access keys in Terraform configuration files poses a significant security risk as these credentials can be exposed if the code is shared, stored in version control systems, or accidentally leaked. This vulnerability could allow unauthorized access to AWS resources, potentially leading to data breaches, resource manipulation, or incurring unexpected costs.

Instead of hardcoding credentials directly in configuration files like `user_data = "1234567890123456789012345678901234567890$"`, use more secure approaches such as referencing files (`file("scripts/first-boot-http.sh")`) or utilizing environment variables, AWS IAM roles, or secure secret management solutions. This helps maintain the principle of least privilege and significantly reduces the risk of credential exposure.


## Compliant Code Examples
```terraform
resource "aws_instance" "negative1" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  user_data = file("scripts/first-boot-http.sh")
  tags = {
    Name = "HelloWorld"
  }
}


```

```terraform
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = "single-instance"

  ami                    = "ami-ebd02392"
  instance_type          = "t2.micro"
  key_name               = "user1"
  monitoring             = true
  vpc_security_group_ids = ["sg-12345678"]
  subnet_id              = "subnet-eddcdzz4"
  user_data = file("scripts/first-boot-http.sh")

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_instance" "positive1" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  user_data = "1234567890123456789012345678901234567890$"
  tags = {
    Name = "HelloWorld"
  }
}


```

```terraform
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = "single-instance"

  ami                    = "ami-ebd02392"
  instance_type          = "t2.micro"
  key_name               = "user1"
  monitoring             = true
  vpc_security_group_ids = ["sg-12345678"]
  subnet_id              = "subnet-eddcdzz4"
  user_data = "1234567890123456789012345678901234567890$"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```