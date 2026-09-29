resource "aws_instance" "web" {
  ami           = "ami-123456"
  instance_type = "t2.micro"
}

resource "aws_s3_bucket" "data" {
  bucket = "my-test-bucket"
  acl    = "private"
}
