resource "terraform_data" "plain" {
  input = "plain"
}
resource "terraform_data" "counted" {
  count = 3
  input = count.index
}
resource "terraform_data" "keyed" {
  for_each = toset(["prod", "staging"])
  input    = each.key
}
resource "terraform_data" "constant" {
  count = 2
  input = "same"
}
resource "terraform_data" "empty_count" {
  count = 0
  input = "x"
}
resource "terraform_data" "empty_each" {
  for_each = {}
  input    = "x"
}
resource "terraform_data" "no_each_read" {
  for_each = toset(["a", "b"])
  input    = "static"
}
data "null_data_source" "d" {
  inputs = { data = "data" }
}

terraform {
  required_providers {
    null = { source = "hashicorp/null" }
  }
}