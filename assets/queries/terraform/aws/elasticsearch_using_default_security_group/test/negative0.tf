resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "example"

  vpc_options {
    security_group_ids = ["sg-12345678"] # ✅ Explicit security group assigned
  }
}
