variable "names" { type = set(string) }
resource "terraform_data" "r" {
  for_each = var.names
  input    = each.key
}
