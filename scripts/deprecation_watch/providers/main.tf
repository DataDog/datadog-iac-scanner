# Provider versions for deprecation_watch (terraform providers schema -json).
# Auto-bumped monthly by the deprecation-watch-bump-providers workflow.
# Manual bump: python3 bump_providers.py && terraform providers lock -platform=linux_amd64 -platform=darwin_amd64

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.82.2"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.17.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "6.14.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.35.1"
    }
    alicloud = {
      source  = "aliyun/alicloud"
      version = "1.239.0"
    }
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "1.81.175"
    }
    databricks = {
      source  = "databricks/databricks"
      version = "1.59.0"
    }
    github = {
      source  = "integrations/github"
      version = "6.4.0"
    }
  }
}
