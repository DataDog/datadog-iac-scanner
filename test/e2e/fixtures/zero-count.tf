variable "enabled" {
  default = false
}

variable "n" {}

resource "aws_s3_bucket" "enabled" {
  bucket = "enabled"
}

resource "aws_s3_bucket" "zero" {
  count  = 0
  bucket = "zero"
}

resource "aws_s3_bucket" "disabled_by_default" {
  count  = var.enabled ? 1 : 0
  bucket = "disabled"
}

resource "aws_s3_bucket" "unknown" {
  count  = var.n
  bucket = "unknown"
}

locals {
  on = var.enabled
}

resource "aws_s3_bucket" "local_flag" {
  count  = local.on ? 1 : 0
  bucket = "local"
}

resource "aws_s3_bucket" "empty_for_each" {
  for_each = var.enabled ? { a = 1 } : {}
  bucket   = "fe"
}
