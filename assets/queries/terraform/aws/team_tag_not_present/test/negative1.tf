resource "aws_s3_bucket" "good_example" {
  bucket = "my-bucket"

  tags = {
    Team = "Security" # ✅ "Team" tag is present
  }
}
