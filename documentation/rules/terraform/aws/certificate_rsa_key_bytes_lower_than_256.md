---
title: "Certificate RSA key bytes lower than 256"
group_id: "Terraform / AWS"
meta:
  name: "aws/certificate_rsa_key_bytes_lower_than_256"
  id: "874d68a3-bfbe-4a4b-aaa0-9e74d7da634b"
  display_name: "Certificate RSA key bytes lower than 256"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `874d68a3-bfbe-4a4b-aaa0-9e74d7da634b`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api)

### Description

This check validates that SSL/TLS certificates used within infrastructure resources, such as API Gateway domain names, employ a sufficiently strong RSA key—specifically, one that is at least 2048 bits (256 bytes) in length. Using an RSA public key that is less than 2048 bits, such as with a 1024-bit certificate (`certificate_body = file("./rsa1024.pem")`), exposes the resource to cryptographic attacks, as shorter keys are more easily compromised by brute-force methods. Attackers that manage to break weak encryption can decrypt traffic, potentially leading to the exposure of sensitive data and unauthorized access to protected APIs and resources. To mitigate these risks, certificates should always be generated with a minimum of a 2048-bit key size (`certificate_body = file("./rsa4096.pem")`), ensuring robust protection for data in transit.

## Compliant Code Examples
```terraform
resource "aws_iam_server_certificate" "test_cert22" {
  name             = "some_test_cert"
  certificate_body = file("./rsa4096.pem")
  private_key      = <<EOF
-----BEGIN RSA PRIVATE KEY-----
[......] # cert contents
-----END RSA PRIVATE KEY-----
EOF
}


```

```terraform
resource "aws_api_gateway_domain_name" "example3" {
  certificate_body = file("./rsa4096.pem")
  domain_name     = "api.example.com"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_server_certificate" "test_cert2" {
  name             = "some_test_cert"
  certificate_body = file("./rsa1024.pem")
  private_key      = <<EOF
-----BEGIN RSA PRIVATE KEY-----
[......] # cert contents
-----END RSA PRIVATE KEY-----
EOF
}

```

```terraform
resource "aws_api_gateway_domain_name" "example" {
  certificate_body = file("./rsa1024.pem")
  domain_name     = "api.example.com"
}

```