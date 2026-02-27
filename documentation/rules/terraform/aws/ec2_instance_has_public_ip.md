---
title: "EC2 instance has public IP"
group_id: "Terraform / AWS"
meta:
  name: "aws/ec2_instance_has_public_ip"
  id: "5a2486aa-facf-477d-a5c1-b010789459ce"
  display_name: "EC2 instance has public IP"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `5a2486aa-facf-477d-a5c1-b010789459ce`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate_public_ip_address)

### Description

EC2 instances should not be assigned public IP addresses directly, as this exposes them to the internet and increases the risk of unauthorized access and attacks. In Terraform, this is configured using the `associate_public_ip_address` attribute. Setting `associate_public_ip_address = true` on an `aws_instance` resource will result in a public IP being attached, whereas `associate_public_ip_address = false` ensures the instance is only accessible within the private network, reducing the attack surface and enhancing the security posture of the environment.

## Compliant Code Examples
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

  network_interface {
    network_interface_id = aws_network_interface.this.id
    device_index         = 0
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

resource "aws_network_interface" "this" {
  subnet_id       = var.private_subnet_id
  security_groups = [aws_security_group.this.id]
}

resource "aws_security_group" "this" {
  name        = "example"
  description = "Example Security Group"
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
  associate_public_ip_address = false

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  associate_public_ip_address = false
  instance_type = "t3.micro"

  tags = {
    Name = "HelloWorld"
  }
}

```
## Non-Compliant Code Examples
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
  associate_public_ip_address = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
data "aws_ami" "ubuntu1" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "web2" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  tags = {
    Name = "HelloWorld"
  }
}

resource "aws_instance" "web3" {
  ami           = data.aws_ami.ubuntu.id
  associate_public_ip_address = true
  instance_type = "t3.micro"

  tags = {
    Name = "HelloWorld"
  }
}

```