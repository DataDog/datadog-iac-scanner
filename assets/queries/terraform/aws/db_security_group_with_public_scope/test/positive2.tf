resource "aws_security_group" "positive2" {
  name        = "db-public-scope"
  description = "Database security group with public scope"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
