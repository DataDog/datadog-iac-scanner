resource "aws_security_group" "negative2" {
  name        = "db-private-scope"
  description = "Database security group with private scope"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/25"]
  }
}
