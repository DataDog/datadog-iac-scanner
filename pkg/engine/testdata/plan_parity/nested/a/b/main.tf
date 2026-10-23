resource "terraform_data" "deep" {
  for_each = toset(["p"])
  input    = each.key
}
