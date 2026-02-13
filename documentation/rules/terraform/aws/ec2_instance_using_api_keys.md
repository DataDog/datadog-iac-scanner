---
title: "EC2 instance using API keys"
group_id: "Terraform / AWS"
meta:
  name: "aws/ec2_instance_using_api_keys"
  id: "0b93729a-d882-4803-bdc3-ac429a21f158"
  display_name: "EC2 instance using API keys"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `0b93729a-d882-4803-bdc3-ac429a21f158`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#iam_instance_profile)

### Description

EC2 instances should use IAM roles to be granted access to other AWS services. Storing AWS credentials directly in user data or on the instance, for example with environment variables such as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, as shown below, exposes sensitive credentials to anyone with access to the instance or the AWS console:

```
user_data = <<EOF
//!/bin/bash
apt-get install -y awscli
export AWS_ACCESS_KEY_ID=your_access_key_id_here
export AWS_SECRET_ACCESS_KEY=your_secret_access_key_here
EOF
```

This misconfiguration creates a significant security risk, as leaked credentials can be used by attackers to gain unauthorized access to AWS resources and potentially compromise the wider AWS environment. Instead, EC2 instances should be granted permissions using IAM roles via the `iam_instance_profile` attribute, which securely delivers temporary credentials to the instance and removes the need to manually manage or expose AWS keys.

## Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role_policy_attachment" "test_attach" {
  roles      = [aws_iam_role.test_role.name]
  policy_arn = aws_iam_policy.test_policy.arn
}

resource "aws_iam_policy" "test_policy" {
  name = "test_policy"
  description = "test policy"
  path = "/"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Action": [
              "s3:Get*",
              "s3:List*"
          ],
          "Effect": "Allow",
          "Resource": "*"
      }
  ]
}
EOF
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  path = "/"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

resource "aws_iam_instance_profile" "test_profile" {
  name = "test_profile"
  role = aws_iam_role.role.name
}

resource "aws_instance" "negative3" {
  ami           = "ami-005e54dee72cc1d00" # us-west-2
  instance_type = "t2.micro"

  tags = {
    Name = "test"
  }

  iam_instance_profile = aws_iam_instance_profile.test_profile.name

  credit_specification {
    cpu_credits = "unlimited"
  }

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
  EOF
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

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role_policy_attachment" "test_attach" {
  roles      = [aws_iam_role.test_role.name]
  policy_arn = aws_iam_policy.test_policy.arn
}

resource "aws_iam_policy" "test_policy" {
  name = "test_policy"
  description = "test policy"
  path = "/"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
      {
          "Action": [
              "s3:Get*",
              "s3:List*"
          ],
          "Effect": "Allow",
          "Resource": "*"
      }
  ]
}
EOF
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  path = "/"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
EOF
}

resource "aws_iam_instance_profile" "test_profile" {
  name = "test_profile"
  role = aws_iam_role.role.name
}

resource "aws_instance" "negative1" {
  ami           = "ami-005e54dee72cc1d00" # us-west-2
  instance_type = "t2.micro"

  tags = {
    Name = "test"
  }

  iam_instance_profile = aws_iam_instance_profile.test_profile.name

  credit_specification {
    cpu_credits = "unlimited"
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "positive6" {
  ami           = "ami-005e54dee72cc1d00" # us-west-2
  instance_type = "t2.micro"

  tags = {
    Name = "test"
  }

  user_data = <<EOT
#cloud-config
repo_update: true
repo_upgrade: all

packages:
 - awscli

runcmd:
 - [ sh, -c, "echo export AWS_ACCESS_KEY_ID=my-key-id >> ~/.bashrc" ]
 - [ sh, -c, "echo export AWS_SECRET_ACCESS_KEY=my-secret >> ~/.bashrc" ]
EOT

  credit_specification {
    cpu_credits = "unlimited"
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

  user_data_base64 = var.init_aws_cli


  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "positive2" {
  ami           = "ami-005e54dee72cc1d00" # us-west-2
  instance_type = "t2.micro"

  tags = {
    Name = "test"
  }

  user_data = <<EOT
#!/bin/bash
apt-get install -y awscli
cat << EOF > ~/.aws/config
[default]
aws_access_key_id = somekey
aws_secret_access_key = somesecret
EOF
EOT

  credit_specification {
    cpu_credits = "unlimited"
  }
}

```