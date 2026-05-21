---
title: "Generic Git module without revision"
group_id: "Terraform"
meta:
  name: "generic_git_module_without_revision"
  id: "terraform-generic-git-module-without-revision"
  display_name: "Generic Git module without revision"
  cloud_provider: ""
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-generic-git-module-without-revision{{< /copyable-code >}}

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/language/modules/sources.html#selecting-a-revision)

### Description

All generic Git module sources should include a revision reference.
Module sources that begin with `git::` must include a `?ref=` parameter to pin the source to a specific commit, tag, or branch. This ensures reproducible and predictable builds.
This rule flags modules where `module.source` starts with `git::` and does not contain `?ref=`.

## Compliant Code Examples
```terraform
variable "cluster_name" {
  default     = "example"
  description = "cluster name"
  type        = string
}

module "acm" {
  source      = "terraform-aws-modules/acm/aws"
  version     = "~> v2.0"
  domain_name = var.site_domain
  zone_id     = data.aws_route53_zone.this.zone_id
  tags        = var.tags

  providers = {
    aws = aws.us_east_1 # cloudfront needs acm certificate to be from "us-east-1" region
  }
}

resource "aws_eks_cluster" "negative1" {
  depends_on                = [aws_cloudwatch_log_group.example]

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  name                      = var.cluster_name
}

```
## Non-Compliant Code Examples
```terraform
variable "cluster_name" {
  default     = "example"
  description = "cluster name"
  type        = string
}

module "acm" {
  source      = "git::https://example.com/vpc.git"
  version     = "~> v2.0"
  domain_name = var.site_domain
  zone_id     = data.aws_route53_zone.this.zone_id
  tags        = var.tags

  providers = {
    aws = aws.us_east_1 # cloudfront needs acm certificate to be from "us-east-1" region
  }
}

resource "aws_eks_cluster" "negative1" {
  depends_on                = [aws_cloudwatch_log_group.example]

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  name                      = var.cluster_name
}

```