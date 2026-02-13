resource "aws_opensearch_domain" "good_example" {
  domain_name = "example"

  vpc_options {
    security_group_ids = ["sg-87654321"] # ✅ Explicit security group assigned
  }
}
