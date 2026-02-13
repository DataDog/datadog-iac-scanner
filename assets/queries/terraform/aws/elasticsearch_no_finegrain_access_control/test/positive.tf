resource "aws_opensearch_domain" "bad_example" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = false # ❌ Fine-grained access control is disabled
    internal_user_database_enabled = false # ❌ Internal user database is disabled
  }
}

resource "aws_elasticsearch_domain" "bad_example2" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = false # ❌ Fine-grained access control is disabled
    internal_user_database_enabled = false # ❌ Internal user database is disabled
  }
}

resource "aws_elasticsearch_domain" "bad_example3" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
  }
}

resource "aws_elasticsearch_domain" "bad_example4" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = false
    internal_user_database_enabled = true
  }
}

resource "aws_elasticsearch_domain" "bad_example5" {
  domain_name = "example"

                                              # ❌ No advanced_security_options block
}
