---
title: "Sensitive port is exposed to wide private network"
group_id: "Terraform / AWS"
meta:
  name: "aws/sensitive_port_is_exposed_to_wide_private_network"
  id: "92fe237e-074c-4262-81a4-2077acb928c1"
  display_name: "Sensitive port is exposed to wide private network"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `92fe237e-074c-4262-81a4-2077acb928c1`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)

### Description

 Leaving sensitive ports such as port 23 (Telnet) or port 110 (POP3) open to a wide private network via insecure security group rules can expose resources to unnecessary risk, as these ports are frequently targeted by attackers seeking to exploit legacy or weakly protected protocols. In Terraform, a misconfiguration, as in the example below, makes internal resources within the VPC accessible to all hosts in the private address range, greatly increasing the attack surface if any host in that range is compromised. :

```
ingress {
  from_port   = 23
  to_port     = 23
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}
```

Restricting access to only necessary subnets and ports significantly reduces the risk of lateral movement and unauthorized access within your network:

```
ingress {
  from_port   = 2383
  to_port     = 2383
  protocol    = "tcp"
  cidr_blocks = [aws_vpc.main.cidr_block]
}
```


## Compliant Code Examples
```terraform
module "vote_service_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.3.0"

  name        = "user-service"
  description = "Security group for user-service with custom ports open within VPC, and PostgreSQL publicly open"
  vpc_id      = "vpc-12345678"

  ingress_with_cidr_blocks = [
    {
      description = "TLS from VPC"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["1.2.3.4", "0.0.0.0/0"]
    }
  ]
}

```

```terraform
resource "aws_security_group" "negative3" {
  name        = "allow_tls3"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 25
    to_port     = 2500
    protocol    = "tcp"
    cidr_blocks = ["1.2.3.4/0"]
  }
}

```

```terraform
resource "aws_security_group" "negative2" {
  name        = "allow_tls2"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 2384
    to_port     = 2386
    protocol    = "tcp"
    cidr_blocks = ["/0"]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_security_group" "positive6" {
  name        = "allow_tls6"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 135
    to_port     = 170
    protocol    = "udp"
    cidr_blocks = ["10.68.0.0", "172.16.0.0/12"]
  }
}

```

```terraform
resource "aws_security_group" "positive2" {
  name        = "allow_tls2"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 20
    to_port     = 60
    protocol    = "tcp"
    cidr_blocks = ["192.168.0.0/16"]
  }
}

```

```terraform
resource "aws_security_group" "positive3" {
  name        = "allow_tls3"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 5000
    to_port     = 6000
    protocol    = "-1"
    cidr_blocks = ["172.16.0.0/12"]
  }
}

```