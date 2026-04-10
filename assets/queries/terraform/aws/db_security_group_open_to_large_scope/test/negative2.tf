resource "aws_security_group" "negative2" {
  name        = "db-small-scope"
  description = "Database security group with restricted scope"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/25"]
  }
}
