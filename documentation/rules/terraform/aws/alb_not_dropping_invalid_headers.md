---
title: "ALB not dropping invalid headers"
group_id: "Terraform / AWS"
meta:
  name: "aws/alb_not_dropping_invalid_headers"
  id: "6e3fd2ed-5c83-4c68-9679-7700d224d379"
  display_name: "ALB not dropping invalid headers"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `6e3fd2ed-5c83-4c68-9679-7700d224d379`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#drop_invalid_header_fields)

### Description

It is recommended to set the `drop_invalid_header_fields` attribute to `true` in AWS Application Load Balancer (`aws_alb`) resources. If this attribute is omitted or set to `false`, as in the examples below, the load balancer will accept and forward malformed or non-standard HTTP header fields to the backend, potentially exposing your application to header-based attacks or unexpected backend behavior:

```
resource "aws_alb" "disabled_1" {
  ...
}

resource "aws_alb" "disabled_2" {
  ...
  drop_invalid_header_fields = false
}
```

Enabling `drop_invalid_header_fields = true` helps mitigate these risks by ensuring only properly formatted HTTP headers are processed.

## Compliant Code Examples
```terraform
resource "aws_alb" "enabled" {
  internal           = false
  name               = "alb"
  subnets            = module.vpc.public_subnets

  drop_invalid_header_fields = true
}

resource "aws_lb" "enabled" {
  internal           = false
  name               = "alb"
  subnets            = module.vpc.public_subnets

  drop_invalid_header_fields = true
}

```

```terraform
resource "aws_lb" "enabled" {
  internal           = false
  load_balancer_type = "application"
  name               = "alb"
  subnets            = module.vpc.public_subnets

  drop_invalid_header_fields = true
}

```

```terraform
resource "aws_alb" "enabled" {
  internal           = false
  load_balancer_type = "application"
  name               = "alb"
  subnets            = module.vpc.public_subnets

  drop_invalid_header_fields = true
}

```
## Non-Compliant Code Examples
```terraform
module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 6.0"

  name = "my-alb"

  vpc_id             = "vpc-abcde012"
  subnets            = ["subnet-abcde012", "subnet-bcde012a"]
  security_groups    = ["sg-edcd9784", "sg-edcd9785"]

  access_logs = {
    bucket = "my-alb-logs"
  }

  target_groups = [
    {
      name_prefix      = "pref-"
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"
      targets = [
        {
          target_id = "i-0123456789abcdefg"
          port = 80
        },
        {
          target_id = "i-a1b2c3d4e5f6g7h8i"
          port = 8080
        }
      ]
    }
  ]

  https_listeners = [
    {
      port               = 443
      protocol           = "HTTPS"
      certificate_arn    = "arn:aws:iam::123456789012:server-certificate/test_cert-123456789012"
      target_group_index = 0
    }
  ]

  http_tcp_listeners = [
    {
      port               = 80
      protocol           = "HTTP"
      target_group_index = 0
    }
  ]

  tags = {
    Environment = "Test"
  }
}

```

```terraform
resource "aws_lb" "disabled_1" {
  internal           = false
  load_balancer_type = "application"
  name               = "alb"
  subnets            = module.vpc.public_subnets
}

resource "aws_lb" "disabled_2" {
  internal           = false
  load_balancer_type = "application"
  name               = "alb"
  subnets            = module.vpc.public_subnets

  drop_invalid_header_fields = false
}

```

```terraform
resource "aws_alb" "disabled_1" {
  internal           = false
  name               = "alb"
  subnets            = module.vpc.public_subnets
}

resource "aws_lb" "disabled_2" {
  internal           = false
  name               = "alb"
  subnets            = module.vpc.public_subnets

  drop_invalid_header_fields = false
}

```