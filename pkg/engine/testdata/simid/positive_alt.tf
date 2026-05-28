# Same resource name as positive.tf but different content.
# simID must be unchanged because it hashes path+queryID+searchKey, not file bytes.
resource "aws_instance" "synth" {
  ami           = "ami-changed"
  instance_type = "t3.micro"
  tags = {
    extra = "property"
  }
}
