resource "aws_db_security_group" "positive2" {
  name = "rds_sg"

  ingress {
    cidr = "10.0.0.0/25"
  }

  ingress {
    cidr = "10.0.0.0/24"
  }
}
