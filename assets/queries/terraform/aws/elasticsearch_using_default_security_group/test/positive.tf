resource "aws_elasticsearch_domain" "bad_example" {
  domain_name = "example"

  vpc_options {
    security_group_ids = []
  }
}

resource "aws_opensearch_domain" "bad_example" {
  domain_name = "example"

  vpc_options {
    security_group_ids = []
  }
}
