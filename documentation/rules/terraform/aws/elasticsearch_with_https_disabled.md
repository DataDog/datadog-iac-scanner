---
title: "Elasticsearch with HTTPS disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_with_https_disabled"
  id: "2e9e0729-66d5-4148-9d39-5e6fb4bf2a4e"
  display_name: "Elasticsearch with HTTPS disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `2e9e0729-66d5-4148-9d39-5e6fb4bf2a4e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https)

### Description

 Amazon Elasticsearch domains should enforce HTTPS by setting the `enforce_https` attribute to `true` in the `domain_endpoint_options` block. If `enforce_https` is left set to `false`, as shown below, communication with the Elasticsearch domain can occur over unencrypted HTTP, exposing data to interception and increasing the risk of man-in-the-middle attacks.

```
domain_endpoint_options {
  enforce_https = false
}
```

To mitigate this, always configure:

```
domain_endpoint_options {
  enforce_https = true
}
```

Enforcing HTTPS ensures that all data transmitted between clients and the Elasticsearch service is encrypted, protecting sensitive information from unauthorized access.


## Compliant Code Examples
```terraform
provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "example" {
  domain_name           = "my-elasticsearch-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t2.small.elasticsearch"
    instance_count = 1
    dedicated_master_enabled = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp2"
    volume_size = 10
  }

  vpc_options {
    subnet_ids         = ["subnet-xxxxxxxx", "subnet-yyyyyyyy"]
    security_group_ids = ["sg-xxxxxxxx"]
  }

  domain_endpoint_options {
    enforce_https = true
  }

  tags = {
    Name        = "my-elasticsearch-domain"
    Environment = "production"
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "example" {
  domain_name           = "my-elasticsearch-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t2.small.elasticsearch"
    instance_count = 1
    dedicated_master_enabled = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp2"
    volume_size = 10
  }

  vpc_options {
    subnet_ids         = ["subnet-xxxxxxxx", "subnet-yyyyyyyy"]
    security_group_ids = ["sg-xxxxxxxx"]
  }

  domain_endpoint_options {
    enforce_https = false
  }

  tags = {
    Name        = "my-elasticsearch-domain"
    Environment = "production"
  }
}

```