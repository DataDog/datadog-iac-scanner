---
title: "Autoscaling groups supply tags"
group_id: "Terraform / AWS"
meta:
  name: "aws/autoscaling_groups_supply_tags"
  id: "ba48df05-eaa1-4d64-905e-4a4b051e7587"
  display_name: "Autoscaling groups supply tags"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `ba48df05-eaa1-4d64-905e-4a4b051e7587`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group#tag-and-tags)

### Description

Autoscaling groups in AWS should be configured with appropriate tags to ensure proper resource management, cost allocation, and identification. When the `tags` attribute is omitted, as in the following example, it becomes difficult to track and manage autoscaling resources, increasing the risk of orphaned or mismanaged infrastructure.

```
resource "aws_autoscaling_group" "example" {
  name                 = "foobar3-terraform-test"
  max_size             = 5
  min_size             = 2
  launch_configuration = aws_launch_configuration.foobar.name
  vpc_zone_identifier  = [aws_subnet.example1.id, aws_subnet.example2.id]
}
```

Adding descriptive tags, as shown below, helps enforce governance, simplifies operations, and supports effective monitoring:

```
resource "aws_autoscaling_group" "example" {
  // ... other configuration ...
  tags = [
    {
      "key"                 = "environment"
      "value"               = "production"
      "propagate_at_launch" = true
    }
  ]
}
```

## Compliant Code Examples
```terraform
module "asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 4.0"

  # Autoscaling group
  name = "example-asg"

  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0
  health_check_type         = "EC2"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]

  initial_lifecycle_hooks = [
    {
      name                  = "ExampleStartupLifeCycleHook"
      default_result        = "CONTINUE"
      heartbeat_timeout     = 60
      lifecycle_transition  = "autoscaling:EC2_INSTANCE_LAUNCHING"
      notification_metadata = jsonencode({ "hello" = "world" })
    },
    {
      name                  = "ExampleTerminationLifeCycleHook"
      default_result        = "CONTINUE"
      heartbeat_timeout     = 180
      lifecycle_transition  = "autoscaling:EC2_INSTANCE_TERMINATING"
      notification_metadata = jsonencode({ "goodbye" = "world" })
    }
  ]

  instance_refresh = {
    strategy = "Rolling"
    preferences = {
      min_healthy_percentage = 50
    }
    triggers = ["tag"]
  }

  # Launch template
  lt_name                = "example-asg"
  description            = "Launch template example"
  update_default_version = true

  use_lt    = true
  create_lt = true

  image_id          = "ami-ebd02392"
  instance_type     = "t3.micro"
  ebs_optimized     = true
  enable_monitoring = true

  block_device_mappings = [
    {
      # Root volume
      device_name = "/dev/xvda"
      no_device   = 0
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 20
        volume_type           = "gp2"
      }
      }, {
      device_name = "/dev/sda1"
      no_device   = 1
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 30
        volume_type           = "gp2"
      }
    }
  ]

  capacity_reservation_specification = {
    capacity_reservation_preference = "open"
  }

  cpu_options = {
    core_count       = 1
    threads_per_core = 1
  }

  credit_specification = {
    cpu_credits = "standard"
  }

  instance_market_options = {
    market_type = "spot"
    spot_options = {
      block_duration_minutes = 60
    }
  }

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 32
  }

  network_interfaces = [
    {
      delete_on_termination = true
      description           = "eth0"
      device_index          = 0
      security_groups       = ["sg-12345678"]
    },
    {
      delete_on_termination = true
      description           = "eth1"
      device_index          = 1
      security_groups       = ["sg-12345678"]
    }
  ]

  placement = {
    availability_zone = "us-west-1b"
  }

  tag_specifications = [
    {
      resource_type = "instance"
      tags          = { WhatAmI = "Instance" }
    },
    {
      resource_type = "volume"
      tags          = { WhatAmI = "Volume" }
    },
    {
      resource_type = "spot-instances-request"
      tags          = { WhatAmI = "SpotInstanceRequest" }
    }
  ]

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

  tags_as_map = {
    extra_tag1 = "extra_value1"
    extra_tag2 = "extra_value2"
  }
}

```

```terraform
resource "aws_autoscaling_group" "negative2" {
  name                 = "foobar3-terraform-test"
  max_size             = 5
  min_size             = 2
  launch_configuration = aws_launch_configuration.foobar.name
  vpc_zone_identifier  = [aws_subnet.example1.id, aws_subnet.example2.id]

  tag {
    key                 = "foo"
    value               = "bar"
    propagate_at_launch = true
  }
}

```

```terraform
resource "aws_autoscaling_group" "negative1" {
  name                 = "foobar3-terraform-test"
  max_size             = 5
  min_size             = 2
  launch_configuration = aws_launch_configuration.foobar.name
  vpc_zone_identifier  = [aws_subnet.example1.id, aws_subnet.example2.id]

  tags = concat(
    [
      {
        "key"                 = "interpolation1"
        "value"               = "value3"
        "propagate_at_launch" = true
      },
      {
        "key"                 = "interpolation2"
        "value"               = "value4"
        "propagate_at_launch" = true
      },
    ],
  )
}

```
## Non-Compliant Code Examples
```terraform
module "asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 4.0"

  # Autoscaling group
  name = "example-asg"

  min_size                  = 0
  max_size                  = 1
  desired_capacity          = 1
  wait_for_capacity_timeout = 0
  health_check_type         = "EC2"
  vpc_zone_identifier       = ["subnet-1235678", "subnet-87654321"]

  initial_lifecycle_hooks = [
    {
      name                  = "ExampleStartupLifeCycleHook"
      default_result        = "CONTINUE"
      heartbeat_timeout     = 60
      lifecycle_transition  = "autoscaling:EC2_INSTANCE_LAUNCHING"
      notification_metadata = jsonencode({ "hello" = "world" })
    },
    {
      name                  = "ExampleTerminationLifeCycleHook"
      default_result        = "CONTINUE"
      heartbeat_timeout     = 180
      lifecycle_transition  = "autoscaling:EC2_INSTANCE_TERMINATING"
      notification_metadata = jsonencode({ "goodbye" = "world" })
    }
  ]

  instance_refresh = {
    strategy = "Rolling"
    preferences = {
      min_healthy_percentage = 50
    }
    triggers = ["tag"]
  }

  # Launch template
  lt_name                = "example-asg"
  description            = "Launch template example"
  update_default_version = true

  use_lt    = true
  create_lt = true

  image_id          = "ami-ebd02392"
  instance_type     = "t3.micro"
  ebs_optimized     = true
  enable_monitoring = true

  block_device_mappings = [
    {
      # Root volume
      device_name = "/dev/xvda"
      no_device   = 0
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 20
        volume_type           = "gp2"
      }
      }, {
      device_name = "/dev/sda1"
      no_device   = 1
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 30
        volume_type           = "gp2"
      }
    }
  ]

  capacity_reservation_specification = {
    capacity_reservation_preference = "open"
  }

  cpu_options = {
    core_count       = 1
    threads_per_core = 1
  }

  credit_specification = {
    cpu_credits = "standard"
  }

  instance_market_options = {
    market_type = "spot"
    spot_options = {
      block_duration_minutes = 60
    }
  }

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 32
  }

  network_interfaces = [
    {
      delete_on_termination = true
      description           = "eth0"
      device_index          = 0
      security_groups       = ["sg-12345678"]
    },
    {
      delete_on_termination = true
      description           = "eth1"
      device_index          = 1
      security_groups       = ["sg-12345678"]
    }
  ]

  placement = {
    availability_zone = "us-west-1b"
  }

  tag_specifications = [
    {
      resource_type = "instance"
      tags          = { WhatAmI = "Instance" }
    },
    {
      resource_type = "volume"
      tags          = { WhatAmI = "Volume" }
    },
    {
      resource_type = "spot-instances-request"
      tags          = { WhatAmI = "SpotInstanceRequest" }
    }
  ]
}

```

```terraform
resource "aws_autoscaling_group" "positive1" {
  name                 = "foobar3-terraform-test"
  max_size             = 5
  min_size             = 2
  launch_configuration = aws_launch_configuration.foobar.name
  vpc_zone_identifier  = [aws_subnet.example1.id, aws_subnet.example2.id]
}

```