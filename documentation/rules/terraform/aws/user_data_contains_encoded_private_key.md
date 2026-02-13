---
title: "User data contains encoded private key"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_data_contains_encoded_private_key"
  id: "443488f5-c734-460b-a36d-5b3f330174dc"
  display_name: "User data contains encoded private key"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `443488f5-c734-460b-a36d-5b3f330174dc`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#user_data_base64)

### Description

 AWS Launch Configuration's `user_data_base64` field should never contain private keys, even if base64 encoded, as this encryption method can be easily reversed by attackers. When private keys are exposed in user data, they can be extracted from the instance metadata or discovered through AWS API calls, compromising the security of all systems using those credentials. Instead of embedding private keys directly in user data, as shown in the insecure example `user_data_base64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpzb21lS2V5"`, use AWS secrets management services like AWS Secrets Manager or Systems Manager Parameter Store, or implement a secure alternative where private keys are safely retrieved during instance startup.


## Compliant Code Examples
```terraform
module "asg" {
  source = "terraform-aws-modules/autoscaling/aws"
  version = "1.0.4"

  # Launch configuration
  lc_name = "example-lc"

  image_id        = "ami-ebd02392"
  instance_type   = "t2.micro"
  security_groups = ["sg-12345678"]
  user_data_base64 = null

  ebs_block_device = [
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
    },
  ]

  root_block_device = [
    {
      volume_size = "50"
      volume_type = "gp2"
    },
  ]

  # Auto scaling group
  asg_name                  = "example-asg"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]
  health_check_type         = "EC2"
  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0

  tags = [
    {
      key                 = "Environment"
      value               = "dev"
      propagate_at_launch = true
    },
    {
      key                 = "Project"
      value               = "megasecret"
      propagate_at_launch = true
    },
  ]
}

```

```terraform
module "asg" {
  source = "terraform-aws-modules/autoscaling/aws"
  version = "1.0.4"

  # Launch configuration
  lc_name = "example-lc"

  image_id        = "ami-ebd02392"
  instance_type   = "t2.micro"
  security_groups = ["sg-12345678"]
  user_data_base64 = "dGVzdA=="

  ebs_block_device = [
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
    },
  ]

  root_block_device = [
    {
      volume_size = "50"
      volume_type = "gp2"
    },
  ]

  # Auto scaling group
  asg_name                  = "example-asg"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]
  health_check_type         = "EC2"
  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0

  tags = [
    {
      key                 = "Environment"
      value               = "dev"
      propagate_at_launch = true
    },
    {
      key                 = "Project"
      value               = "megasecret"
      propagate_at_launch = true
    },
  ]
}

```

```terraform
module "asg" {
  source = "terraform-aws-modules/autoscaling/aws"
  version = "1.0.4"

  # Launch configuration
  lc_name = "example-lc"

  image_id        = "ami-ebd02392"
  instance_type   = "t2.micro"
  security_groups = ["sg-12345678"]
  user_data_base64 = ""

  ebs_block_device = [
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
    },
  ]

  root_block_device = [
    {
      volume_size = "50"
      volume_type = "gp2"
    },
  ]

  # Auto scaling group
  asg_name                  = "example-asg"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]
  health_check_type         = "EC2"
  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0

  tags = [
    {
      key                 = "Environment"
      value               = "dev"
      propagate_at_launch = true
    },
    {
      key                 = "Project"
      value               = "megasecret"
      propagate_at_launch = true
    },
  ]
}

```
## Non-Compliant Code Examples
```terraform
module "positive2" {
  source = "terraform-aws-modules/autoscaling/aws"
  version = "1.0.4"

  # Launch configuration
  lc_name = "example-lc"

  image_id        = "ami-ebd02392"
  instance_type   = "t2.micro"
  security_groups = ["sg-12345678"]
  user_data_base64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpzb21lS2V5"

  ebs_block_device = [
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
    },
  ]

  root_block_device = [
    {
      volume_size = "50"
      volume_type = "gp2"
    },
  ]

  # Auto scaling group
  asg_name                  = "example-asg"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]
  health_check_type         = "EC2"
  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0

  tags = [
    {
      key                 = "Environment"
      value               = "dev"
      propagate_at_launch = true
    },
    {
      key                 = "Project"
      value               = "megasecret"
      propagate_at_launch = true
    },
  ]
}

```

```terraform
module "positive3" {
  source = "terraform-aws-modules/autoscaling/aws"
  version = "1.0.4"

  # Launch configuration
  lc_name = "example-lc"

  image_id        = "ami-ebd02392"
  instance_type   = "t2.micro"
  security_groups = ["sg-12345678"]
  user_data_base64 = "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZIEJMT0NLLS0tLS0="

  ebs_block_device = [
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
    },
  ]

  root_block_device = [
    {
      volume_size = "50"
      volume_type = "gp2"
    },
  ]

  # Auto scaling group
  asg_name                  = "example-asg"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]
  health_check_type         = "EC2"
  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0

  tags = [
    {
      key                 = "Environment"
      value               = "dev"
      propagate_at_launch = true
    },
    {
      key                 = "Project"
      value               = "megasecret"
      propagate_at_launch = true
    },
  ]
}

```

```terraform
resource "aws_launch_configuration" "positive1" {
  image_id      = data.aws_ami.ubuntu.id
  instance_type = "m4.large"
  spot_price    = "0.001"
  user_data_base64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpzb21lS2V5" # someKey

  lifecycle {
    create_before_destroy = true
  }
}

```