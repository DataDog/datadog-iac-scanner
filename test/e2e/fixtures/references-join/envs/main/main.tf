module "a" {
  source = "../../modules/net"
  n      = 2
}

module "b" {
  source = "../../modules/net"
  n      = 1
}
