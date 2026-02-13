resource "aws_s3_bucket" "good_example" {
  bucket = "my-bucket"

  tags = {
    team = "Security" # ✅ "team" tag is present
  }
}
