---
title: "Security group with unrestricted access to SSH"
group_id: "Terraform / AWS"
meta:
  name: "aws/security_group_with_unrestricted_access_to_ssh"
  id: "65905cec-d691-4320-b320-2000436cb696"
  display_name: "Security group with unrestricted access to SSH"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `65905cec-d691-4320-b320-2000436cb696`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)

### Description

 This check verifies that AWS security groups do not allow unrestricted inbound access to port 22 (SSH) from the public internet (`cidr_blocks = ["0.0.0.0/0"]`). Allowing public SSH access exposes instances to unauthorized access attempts and automated attacks, increasing the risk of successful brute-force compromises. To mitigate this vulnerability, the `cidr_blocks` attribute in the `ingress` block should be restricted to trusted IP ranges only, as shown below:

Insecure configuration:
```
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```

Secure configuration:
```
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["192.120.0.0/16", "75.132.0.0/16"]
}
```
If left unaddressed, this misconfiguration can lead to remote attackers gaining entry to instances via SSH, putting sensitive data and critical infrastructure at risk.


## Compliant Code Examples
```terraform
module "vote_service_sg" {
  source = "terraform-aws-modules/security-group/aws"
  version = "4.3.0"
  name        = "user-service"
  description = "Security group for user-service with custom ports open within VPC, and PostgreSQL publicly open"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.120.0.0/16", "75.132.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

```

```terraform

resource "aws_security_group" "negative1" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.120.0.0/16", "75.132.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_security_group" "positive2" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.120.0.0/16", "0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

```

```terraform
module "vote_service_sg" {
  source = "terraform-aws-modules/security-group/aws"
  version = "4.3.0"
  name        = "user-service"
  description = "Security group for user-service with custom ports open within VPC, and PostgreSQL publicly open"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

```

```terraform
module "vote_service_sg" {
  source = "terraform-aws-modules/security-group/aws"
  version = "4.3.0"
  name        = "user-service"
  description = "Security group for user-service with custom ports open within VPC, and PostgreSQL publicly open"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.120.0.0/16", "0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

```