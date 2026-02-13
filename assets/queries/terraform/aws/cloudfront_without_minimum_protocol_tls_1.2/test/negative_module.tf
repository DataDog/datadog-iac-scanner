module "my_distribution" {
  source = "terraform-aws-modules/cloudfront/aws"
  version = "~> 3.0"

  aliases = ["mysite.example.com"]

  comment             = "Some comment"
  enabled             = true
  default_root_object = "index.html"
  is_ipv6_enabled     = true
  price_class         = "PriceClass_100"
  retain_on_delete    = false
  wait_for_deployment = true
  tags = {
    my-products = "cloudfront"
  }

  create_origin_access_identity = true
  origin_access_identities = {
    s3_bucket_one = "My awesome CloudFront can access"
    s3_bucket_two = "CloudFront can also access this one"
  }

  origin = [
    {
      s3_origin_config = {
        origin_access_identity = "s3_bucket_one"
      }
      domain_name = "MY_S3_DNS_NAME"
      origin_id   = "S3-my-group"
    },
    {
      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_keepalive_timeout = 5
        origin_protocol_policy = "match-viewer"
        origin_read_timeout    = 30
        origin_ssl_protocols   = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"]
      }
      domain_name = "MY_DOMAIN"
      origin_id   = "stable"
      origin_path = "/some-path"
      custom_header = {
        name  = "x-authentication-token"
        value = "123456aaabbbcc"
      }
    }
  ]

  default_cache_behavior = {
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["GET", "HEAD"]
    target_origin_id           = "S3-my-group"
    viewer_protocol_policy     = "allow-all"
    compress                   = true
    query_string               = false
    query_string_cache_keys    = ["querystring1"]
    cookie_forward             = "all"
    lambda_function_association = {
      event_type = "viewer-request"
      lambda_arn = "arn:aws:lambda:us-east-1:123456789012:function:static-web-content"
    }
  }

  ordered_cache_behavior = [
    {
      path_pattern     = "/content/immutable/*"
      allowed_methods  = ["GET", "HEAD"]
      cached_methods   = ["GET", "HEAD"]
      target_origin_id = "S3-my-group"

      forwarded_values = {
        query_string = false
        headers      = ["Origin"]
        cookies = {
          forward = "none"
        }
      }

      min_ttl                = 0
      default_ttl            = 86400
      max_ttl                = 31536000
      compress               = true
      viewer_protocol_policy = "redirect-to-https"
      lambda_function_association = {
        event_type   = "viewer-response"
        lambda_arn   = "arn:aws:lambda:us-east-1:123456789012:function:static-web-content"
        include_body = "false"
      }
    },
    {
      path_pattern           = "/content/*"
      allowed_methods        = ["GET", "HEAD", "OPTIONS"]
      cached_methods         = ["GET", "HEAD"]
      target_origin_id       = "S3-my-group"
      compress               = true
      viewer_protocol_policy = "redirect-to-https"

      forwarded_values = {
        query_string = false
        headers      = ["Origin"]
        cookies = {
          forward = "none"
        }
      }
    }
  ]

  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.2_2021"
  }

  logging_config = {
    include_cookies = false
    bucket          = "my_logs.s3.amazonaws.com"
    prefix          = "myprefix"
  }

  restriction = {
    locations = ["US", "CA", "GB", "DE"]
  }
}