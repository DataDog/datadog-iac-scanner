---
title: "ALB listening on HTTP"
group_id: "Terraform / AWS"
meta:
  name: "aws/alb_listening_on_http"
  id: "de7f5e83-da88-4046-871f-ea18504b1d43"
  display_name: "ALB listening on HTTP"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `de7f5e83-da88-4046-871f-ea18504b1d43`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener)

### Description

This check verifies that AWS Application Load Balancers (ALBs) are not configured to listen for incoming traffic on unencrypted HTTP ports (typically port 80). Allowing an ALB to accept HTTP traffic without redirecting it to HTTPS exposes sensitive data to potential interception, as communication is not encrypted in transit. Insecure configurations, such as setting the `protocol` parameter within an `aws_lb_listener` to `"HTTP"` without ensuring a redirect to `"HTTPS"`, can result in data breaches or man-in-the-middle attacks.

## Compliant Code Examples
```terraform
provider "aws2" {
  profile = "default"
  region  = "us-west-2"
}

data "aws_availability_zones" "available2" {
  state = "available"
}

data "aws_ami" "ubuntu2" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_vpc" "vpc1" {
  cidr_block = "10.10.0.0/16"
}

resource "aws_subnet" "subnet12" {
  vpc_id = aws_vpc.vpc1.id
  cidr_block = "10.10.10.0/24"
  availability_zone_id = data.aws_availability_zones.available2.zone_ids[0]
  tags = {
    Name = "subnet1"
  }
}

resource "aws_subnet" "subnet22" {
  vpc_id = aws_vpc.vpc1.id
  cidr_block = "10.10.11.0/24"
  availability_zone_id = data.aws_availability_zones.available2.zone_ids[1]

  tags = {
    Name = "subnet2"
  }
}

resource "aws_lb" "test2" {
  name = "test123"
  load_balancer_type = "application"
  subnets = [aws_subnet.subnet12.id, aws_subnet.subnet22.id]
  internal = true
}

resource "aws_lb_target_group" "test2" {
  port = 80
  protocol = "HTTP"
  target_type = "instance"
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_default_security_group" "dsg2" {
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_lb_listener" "listener2" {
  load_balancer_arn = aws_lb.test2.arn
  protocol = "HTTPS"
  port = 80
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.test2.arn
  }
}

resource "aws_lb_target_group_attachment" "attach12" {
  target_group_arn = aws_lb_target_group.test2.arn
  target_id = aws_instance.inst12.id
  port = 80
}

resource "aws_instance" "inst12" {
  vpc_security_group_ids = [aws_default_security_group.dsg2.id]
  subnet_id = aws_subnet.subnet12.id
  ami = data.aws_ami.ubuntu2.id
  instance_type = "t3.micro"
}

resource "aws_lb_target_group_attachment" "attach22" {
  target_group_arn = aws_lb_target_group.test2.arn
  target_id = aws_instance.inst22.id
  port = 80
}

resource "aws_instance" "inst22" {
  vpc_security_group_ids = [aws_default_security_group.dsg2.id]
  subnet_id = aws_subnet.subnet12.id
  ami = data.aws_ami.ubuntu2.id
  instance_type = "t3.micro"
}

resource "aws_lb_target_group_attachment" "attach32" {
  target_group_arn = aws_lb_target_group.test2.arn
  target_id = aws_instance.inst32.id
  port = 80
}

resource "aws_instance" "inst32" {
  vpc_security_group_ids = [aws_default_security_group.dsg2.id]
  subnet_id = aws_subnet.subnet12.id
  ami = data.aws_ami.ubuntu2.id
  instance_type = "t3.micro"
}

```

```terraform
resource "aws_lb_listener" "listener55" {
  load_balancer_arn = aws_lb.test33.arn
  port = 80
  default_action {
    type = "redirect"

    redirect {
      port        = "80"
      protocol    = "HTTPS"
      status_code = "HTTPS_301"
    }
  }
}

resource "aws_lb" "test33" {
  name = "test123"
  load_balancer_type = "application"
  subnets = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  internal = true
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  profile = "default"
  region  = "us-west-2"
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_vpc" "vpc1" {
  cidr_block = "10.10.0.0/16"
}

resource "aws_subnet" "subnet1" {
  vpc_id               = aws_vpc.vpc1.id
  cidr_block           = "10.10.10.0/24"
  availability_zone_id = data.aws_availability_zones.available.zone_ids[0]
  tags = {
    Name = "subnet1"
  }
}

resource "aws_subnet" "subnet2" {
  vpc_id               = aws_vpc.vpc1.id
  cidr_block           = "10.10.11.0/24"
  availability_zone_id = data.aws_availability_zones.available.zone_ids[1]

  tags = {
    Name = "subnet2"
  }
}

resource "aws_lb" "test" {
  name               = "test123"
  load_balancer_type = "application"
  subnets            = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  internal           = true
}

resource "aws_lb_target_group" "test" {
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.vpc1.id
}

resource "aws_default_security_group" "dsg" {
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.test.arn
  port              = 80
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.test.arn
  }
}

resource "aws_lb_target_group_attachment" "attach1" {
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.inst1.id
  port             = 80
}

resource "aws_instance" "inst1" {
  vpc_security_group_ids = [aws_default_security_group.dsg.id]
  subnet_id              = aws_subnet.subnet1.id
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
}

resource "aws_lb_target_group_attachment" "attach2" {
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.inst2.id
  port             = 80
}

resource "aws_instance" "inst2" {
  vpc_security_group_ids = [aws_default_security_group.dsg.id]
  subnet_id              = aws_subnet.subnet1.id
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
}

resource "aws_lb_target_group_attachment" "attach3" {
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.inst3.id
  port             = 80
}

resource "aws_instance" "inst3" {
  vpc_security_group_ids = [aws_default_security_group.dsg.id]
  subnet_id              = aws_subnet.subnet1.id
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
}

```

```terraform
resource "aws_lb_listener" "listener5" {
  load_balancer_arn = aws_lb.test3.arn
  port = 80
  default_action {
    type = "redirect"

    redirect {
      port        = "80"
      protocol    = "HTTP"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb" "test3" {
  name = "test123"
  load_balancer_type = "application"
  subnets = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  internal = true
}

```