---
title: "EC2 not EBS optimized"
group_id: "Terraform / AWS"
meta:
  name: "aws/ec2_not_ebs_optimized"
  id: "60224630-175a-472a-9e23-133827040766"
  display_name: "EC2 not EBS optimized"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `60224630-175a-472a-9e23-133827040766`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs_optimized)

### Description

 Ensuring that an EC2 instance uses EBS optimization is important for maximizing the performance of attached EBS volumes, as this setting reduces contention between EBS I/O and other instance traffic. If the `ebs_optimized` attribute is not enabled, disk operations may experience degraded performance, leading to slower application response times and potential reliability issues under load. To remediate this, set `ebs_optimized = true` in your instance configuration, as shown below:

```
resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  ebs_optimized = true

  tags = {
    Name = "HelloWorld"
  }
}
```


## Compliant Code Examples
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
  instance_type = "t3.nano"
  ebs_optimized = false

  tags = {
    Name = "HelloWorld"
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
  instance_type = "t3.nano"

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
  instance_type          = "t3.nano"
  key_name               = "user1"
  monitoring             = true
  vpc_security_group_ids = ["sg-12345678"]
  subnet_id              = "subnet-eddcdzz4"
  associate_public_ip_address = false
  ebs_optimized = false

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```
## Non-Compliant Code Examples
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
  instance_type = "t2.micro"
  ebs_optimized = false

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
  associate_public_ip_address = false

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
  ebs_optimized          = false
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