---
title: "Sensitive port is exposed to small public network"
group_id: "Terraform / AWS"
meta:
  name: "aws/sensitive_port_is_exposed_to_small_public_network"
  id: "e35c16a2-d54e-419d-8546-a804d8e024d0"
  display_name: "Sensitive port is exposed to small public network"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e35c16a2-d54e-419d-8546-a804d8e024d0`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)

### Description

Opening sensitive ports such as port 23 (Telnet) or port 110 (POP3) to even small public network ranges in security groups allows untrusted or unauthorized traffic to reach services that are known to have vulnerabilities or lack modern security protections. Attackers can exploit these open ports to gain unauthorized access, launch brute-force attacks, or intercept sensitive data, depending on the service listening on these ports. If this misconfiguration is left unaddressed, it increases the attack surface of your cloud environment and heightens the risk of data breaches, lateral movement within the network, or full system compromise. Properly restricting access to sensitive ports by limiting source IP ranges and disabling unused services is critical for maintaining a secure environment.

## Compliant Code Examples
```terraform
resource "aws_security_group" "negative1" {
  name        = "allow_tls1"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 2383
    to_port     = 2383
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}


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


resource "aws_security_group" "negative4" {
  name        = "allow_tls4"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 25
    to_port     = 2500
    protocol    = "tcp"
    cidr_blocks = ["1.2.3.4/5"]
  }
}


resource "aws_security_group" "negative5" {
  name        = "allow_tls5"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 25
    to_port     = 2500
    protocol    = "udp"
    cidr_blocks = ["1.2.3.4/5","0.0.0.0/12"]
  }
}


resource "aws_security_group" "negative6" {
  name        = "allow_tls6"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["1.2.3.4","0.0.0.0/0"]
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_security_group" "positive1" {
  name        = "allow_tls1"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 2200
    to_port     = 2500
    protocol    = "-1"
    cidr_blocks = ["12.0.0.0/25"]
  }
}


resource "aws_security_group" "positive2" {
  name        = "allow_tls2"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 20
    to_port     = 60
    protocol    = "tcp"
    cidr_blocks = ["1.2.3.4/26"]
  }
}


resource "aws_security_group" "positive3" {
  name        = "allow_tls3"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 5000
    to_port     = 6000
    protocol    = "-1"
    cidr_blocks = ["2.12.22.33/27"]
  }
}


resource "aws_security_group" "positive4" {
  name        = "allow_tls4"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 20
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.92.168.0/28"]
  }
}


resource "aws_security_group" "positive5" {
  name        = "allow_tls5"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 445
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = ["1.1.1.1/29","0.0.0.0/0",  "2.2.3.4/12"]
  }
}


resource "aws_security_group" "positive6" {
  name        = "allow_tls6"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 135
    to_port     = 170
    protocol    = "udp"
    cidr_blocks = ["10.68.0.0", "0.0.0.0/28"]
  }
}


resource "aws_security_group" "positive7" {
  name        = "allow_tls7"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 2383
    to_port     = 2383
    protocol    = "udp"
    cidr_blocks = ["/0", "1.2.3.4/27"]
  }
}


resource "aws_security_group" "positive8" {
  name        = "allow_tls8"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "TLS from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.68.0.0/26"]
  }
}

```