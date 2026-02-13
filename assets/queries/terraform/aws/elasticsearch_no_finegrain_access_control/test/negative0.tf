resource "aws_opensearch_domain" "good_example" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = true # ✅ Fine-grained access control is enabled
    internal_user_database_enabled = true # ✅ Internal user database is enabled
  }
}
