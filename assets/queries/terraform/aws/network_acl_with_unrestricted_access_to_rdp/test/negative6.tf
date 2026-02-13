provider "aws" {
    region = "us-east-1"
  }

  terraform {
    required_providers {
      aws = {
        source  = "hashicorp/aws"
        version = "~> 3.0"
      }
    }
  }

  # This should NOT be flagged - denying RDP from all IPs is SECURE
  resource "aws_network_acl" "negative6" {
    vpc_id = aws_vpc.main.id

    tags = {
      Name = "deny-all-rdp"
    }
  }

  resource "aws_network_acl_rule" "negative6" {
    network_acl_id = aws_network_acl.negative6.id
    rule_number    = 100
    egress         = false
    protocol       = "tcp"
    rule_action    = "deny"        # ← KEY: Denying access
    cidr_block     = "0.0.0.0/0"   # ← From ALL IPs
    from_port      = 3389          # ← RDP port
    to_port        = 3389
  }
