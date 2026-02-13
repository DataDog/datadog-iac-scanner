---
title: "CloudFront without minimum protocol TLS 1.2"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudfront_without_minimum_protocol_tls_1.2"
  id: "00e5e55e-c2ff-46b3-a757-a7a1cd802456"
  display_name: "CloudFront without minimum protocol TLS 1.2"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `00e5e55e-c2ff-46b3-a757-a7a1cd802456`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution)

### Description

 Amazon CloudFront distributions should enforce a minimum TLS protocol version of at least TLS 1.2 to ensure secure encryption between clients and CloudFront. Allowing earlier versions such as TLS 1.0 or TLS 1.1 exposes distributions to known vulnerabilities and weak ciphers, increasing the risk of data interception and man-in-the-middle attacks. This can be securely enforced in Terraform using the `viewer_certificate` block with `minimum_protocol_version = "TLSv1.2_2018"` or higher, as shown below:

```
viewer_certificate {
  cloudfront_default_certificate = false
  minimum_protocol_version = "TLSv1.2_2018"
}
```


## Compliant Code Examples
```terraform
resource "aws_cloudfront_distribution" "negative1" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.2_2018"
  }
}

resource "aws_cloudfront_distribution" "negative2" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.2_2019"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudfront_distribution" "positive2" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    #settings
  }

  restrictions {
    #restrictions
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1_2016"
  }
}

```

```terraform
resource "aws_cloudfront_distribution" "positive3" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    #settings
  }

  restrictions {
    #restrictions
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

```

```terraform
resource "aws_cloudfront_distribution" "positive4" {
  origin {
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = "origin-access-identity/cloudfront/ABCDEFG1234567"
    }
  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    #settings
  }

  restrictions {
    #restrictions
  }

  viewer_certificate {
    cloudfront_default_certificate = false
  }
}

```