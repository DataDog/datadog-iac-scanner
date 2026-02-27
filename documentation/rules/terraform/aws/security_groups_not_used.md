---
title: "Security group not used"
group_id: "Terraform / AWS"
meta:
  name: "aws/security_groups_not_used"
  id: "4849211b-ac39-479e-ae78-5694d506cb24"
  display_name: "Security group not used"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `4849211b-ac39-479e-ae78-5694d506cb24`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)

### Description

This check ensures that AWS load balancers are associated with appropriate security groups, which control network traffic to and from the resource. When the `security_groups` attribute is omitted from an `aws_lb` resource, as shown below, the load balancer may become exposed to unrestricted network access, increasing the risk of unauthorized access or attacks:

```
resource "aws_lb" "test" {
  name = "test"
  load_balancer_type = "application"
  subnets = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  internal = true
}
```

By explicitly defining `security_groups`, you can restrict inbound and outbound traffic to only trusted sources:

```
resource "aws_lb" "test" {
  name = "test"
  load_balancer_type = "application"
  subnets = [aws_subnet.subnet1.id, aws_subnet.subnet2.id]
  internal = true
  security_groups = [aws_security_group.allow_tls.id]
}
```

## Compliant Code Examples
```terraform
# given:
#  - used security group
#  - aws_instance
# when:
#  - used security group attached to aws_instance
# then:
#  - do not detect any unused security group

resource "aws_security_group" "used_sg" {
  name        = "used-sg"
  description = "Used security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "Some port"
    from_port        = 43
    to_port          = 43
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

}

resource "aws_instance" "negative3" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"

  vpc_security_group_ids = [ "aws_security_group.used_sg.id" ]

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

module "security_groups_test" {
  source  = "terraform-aws-modules/security-group/aws//modules/http-80"
  version = "4.3.0"

  name = "web-server"

  security_group_id = aws_security_group.allow_tls.id
}

```

```terraform
resource "aws_security_group" "example" {
  name        = "example"
  description = "Allow Redis traffic"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "Example"
  parameter_group_name       = "default.redis6.x"
  engine                     = "redis"
  engine_version             = "6.x"
  automatic_failover_enabled = false

  security_group_ids = [aws_security_group.example.id]
}
```
## Non-Compliant Code Examples
```terraform
# given:
#  - unused security group
#  - aws_instance
# when:
#  - no security group attached to aws_instance
# then:
#  - detect unused security group as unused

resource "aws_instance" "positive1" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"
}

resource "aws_security_group" "unused-sg" {
  name        = "unused-sg"
  description = "Unused security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "Some port"
    from_port        = 42
    to_port          = 42
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

}

```

```terraform
# given:
#  - unused security group
#  - used security group
#  - aws_instance
# when:
#  - used security group attached to aws_instance
#  - unused security group not attached to aws_instance
# then:
#  - detect only unused security group as unused

resource "aws_instance" "positive1" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"

  vpc_security_group_ids = [ aws_security_group.used_sg.id ]
}

resource "aws_security_group" "unused_sg" {
  name        = "unused-sg"
  description = "Unused security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "Some port"
    from_port        = 42
    to_port          = 42
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

}

resource "aws_security_group" "used_sg" {
  name        = "used-sg"
  description = "Used security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "Some port"
    from_port        = 43
    to_port          = 43
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

}


```

```terraform
# given:
#  - unused security group
#  - used security group
#  - aws_eks_cluster
# when:
#  - used security group attached to aws_eks_cluster
#  - unused security group not attached to aws_eks_cluster
# then:
#  - detect only unused security group as unused

resource "aws_eks_cluster" "positive4" {
  name = "beautiful-eks"

  role_arn = aws_iam_role.example.arn

  vpc_config {
    security_group_ids = [ aws_security_group.used_sg.id ]
  }
}

resource "aws_security_group" "unused_sg" {
  name        = "unused-sg"
  description = "Unused security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "Some port"
    from_port        = 42
    to_port          = 42
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

}

resource "aws_security_group" "used_sg" {
  name        = "used-sg"
  description = "Used security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "Some port"
    from_port        = 43
    to_port          = 43
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

}

```