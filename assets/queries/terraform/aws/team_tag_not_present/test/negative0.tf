resource "aws_instance" "good_example" {
  ami           = "ami-123456"
  instance_type = "t2.micro"

  tags = {
    Team        = "DevOps" # ✅ "Team" tag is present
    Environment = "Production"
  }
}
