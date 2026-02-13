---
title: "Launch configuration is not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/launch_configuration_is_not_encrypted"
  id: "4de9de27-254e-424f-bd70-4c1e95790838"
  display_name: "Launch configuration is not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `4de9de27-254e-424f-bd70-4c1e95790838`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_configuration#encrypted)

### Description

 AWS Launch Configurations with unencrypted EBS volumes expose sensitive data to potential unauthorized access if the physical storage is compromised or the volume is improperly decommissioned. When data is stored unencrypted, it could allow attackers who gain access to the raw storage to extract sensitive information without needing additional credentials. To properly secure your data, always set the `encrypted` parameter to true in all block device configurations, as shown below:

```hcl
ebs_block_device {
  device_name = "/dev/xvda1"
  encrypted = true
}
```

The following is an example of a vulnerable configuration:

```hcl
ebs_block_device {
  device_name = "/dev/xvda1"
  encrypted = false  // or parameter omitted entirely
}
```


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

  ebs_block_device = [
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
      encrypted             = true
    }
 ]

  root_block_device = [ 
    {
      volume_size = "50"
      volume_type = "gp2"
      encrypted   = true
    }
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
resource "aws_launch_configuration" "negative1" {
  image_id      = data.aws_ami.ubuntu.id
  instance_type = "m4.large"
  spot_price    = "0.001"
  user_data_base64 = "c29tZUtleQ==" # someKey

  lifecycle {
    create_before_destroy = true
  }

  ebs_block_device {
    device_name = "/dev/xvda1"
    encrypted = true
  }
}

resource "aws_launch_configuration" "negative2" {
  name = "test-launch-config"

  ephemeral_block_device {
    encrypted = false
  }
}

```
## Non-Compliant Code Examples
```terraform
module "asg" {
  source = "terraform-aws-modules/autoscaling/aws"
  version = "1.0.4"

  # Launch configuration
  lc_name = "example-lc"

  image_id        = "ami-ebd02392"
  instance_type   = "t2.micro"
  security_groups = ["sg-12345678"]

  ebs_block_device = [
     {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
    }
  ]

  root_block_device = [
     {
      volume_size = "50"
      volume_type = "gp2"
     }
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

  ebs_block_device = [ 
    {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
      encrypted             = false
    }
  ]

  root_block_device = [ 
    {
      volume_size = "50"
      volume_type = "gp2"
    }
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

  ebs_block_device = [
     {
      device_name           = "/dev/xvdz"
      volume_type           = "gp2"
      volume_size           = "50"
      delete_on_termination = true
     }
  ]

  root_block_device = [
    {
      volume_size = "50"
      volume_type = "gp2"
      encrypted   = false
    }
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