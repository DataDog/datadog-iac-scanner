resource "aws_instance" "bad_example" {
  ami           = "ami-123456"
  instance_type = "t2.micro"

  tags = {
    Environment = "Production" # ❌ Missing "Team" tag
  }
}

resource "aws_s3_bucket" "bad_example" {
  bucket = "my-bucket"

  # ❌ No tags at all
}
