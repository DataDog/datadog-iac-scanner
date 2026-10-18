resource "terraform_data" "keys" {
  for_each = toset([",", "\\", ""])
  input    = each.key
}
