resource "aws_security_group" "positive2" {
  name        = "db-large-scope"
  description = "Database security group open to large scope"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
}
