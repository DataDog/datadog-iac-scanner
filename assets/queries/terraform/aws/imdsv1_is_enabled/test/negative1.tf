resource "aws_launch_template" "good_example" {
  name_prefix   = "example"
  image_id      = "ami-123456"
  instance_type = "t2.micro"

  metadata_options {
    http_tokens = "required" # ✅ Secure
  }
}
