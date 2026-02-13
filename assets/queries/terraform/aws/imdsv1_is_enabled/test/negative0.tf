resource "aws_instance" "good_example" {
  ami           = "ami-123456"
  instance_type = "t2.micro"

  metadata_options {
    http_tokens = "required" # ✅ Secure
  }
}
