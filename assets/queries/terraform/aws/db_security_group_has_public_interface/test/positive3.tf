resource "aws_security_group" "positive3" {
  name        = "db-public-access"
  description = "Database security group with public access"
  vpc_id      = "vpc-123456"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
