module "b" {
  source = "./b"
}
resource "terraform_data" "leaf" {
  count = 2
  input = count.index
}
