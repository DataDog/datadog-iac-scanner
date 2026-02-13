---
title: "Security group rule without description"
group_id: "Terraform / AWS"
meta:
  name: "aws/security_group_rules_without_description"
  id: "68eb4bf3-f9bf-463d-b5cf-e029bb446d2e"
  display_name: "Security group rule without description"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `68eb4bf3-f9bf-463d-b5cf-e029bb446d2e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#description)

### Description

 All rules within an AWS security group should have descriptive text provided for each rule. Including a `description` for both `ingress` and `egress` rules makes it easier to understand the purpose and intent behind each rule, improving the maintainability and auditability of your security configurations. Without descriptive annotations, security teams may struggle to identify the rationale for specific rules, increasing the risk of misconfigurations or inadvertent exposure of resources. Leaving descriptions blank can lead to confusion, make incident response more difficult, and may undermine compliance efforts that require clear documentation of network security controls.


## Compliant Code Examples
```terraform
resource "aws_security_group" "negative3" {

  name        = "${var.prefix}-external-http-https"
  description = "Allow main HTTP / HTTPS"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.prefix}-external-http-https"
  }
}

resource "aws_security_group_rule" "negative3a" {

  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.negative3.id
  type              = "ingress"
  description       = "Enable HTTP access for select VMs"
}

resource "aws_security_group_rule" "negative3b" {

  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.negative3.id
  type              = "ingress"
  description       = "Enable HTTPS access for select VMs"
}

```

```terraform
resource "aws_security_group" "negative2" {

  name        = "${var.prefix}-external-http-https"
  description = "Allow main HTTP / HTTPS"
  vpc_id      = local.vpc_id

  ingress {
    description = "Enable HTTP access for select VMs"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Enable HTTPS access for select VMs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.prefix}-external-http-https"
  }
}

```

```terraform
resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.main.cidr_block]
    ipv6_cidr_blocks = [aws_vpc.main.ipv6_cidr_block]
  }

  tags = {
    Name = "allow_tls"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_security_group" "positive2" { 

  name        = "${var.prefix}-external-http-https"
  description = "Allow main HTTP / HTTPS"
  vpc_id      = local.vpc_id

  ingress {
    description = "Enable HTTP access for select VMs"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.prefix}-external-http-https"
  }
}

```

```terraform
resource "aws_security_group" "positive3" {

  name        = "${var.prefix}-external-http-https"
  description = "Allow main HTTP / HTTPS"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.prefix}-external-http-https"
  }
}

resource "aws_security_group_rule" "positive3a" {

  description       = "Enable HTTP access for select VMs"
  from_port         = 80
  to_port           = 80
  cidr_blocks       = ["0.0.0.0/0"]
  protocol          = "tcp"
  security_group_id = aws_security_group.positive3.id
  type              = "ingress"
}

resource "aws_security_group_rule" "positive3b" {

  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
  protocol          = "tcp"
  security_group_id = aws_security_group.positive3.id
  type              = "ingress"
}

```

```terraform
resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.main.cidr_block]
    ipv6_cidr_blocks = [aws_vpc.main.ipv6_cidr_block]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

```