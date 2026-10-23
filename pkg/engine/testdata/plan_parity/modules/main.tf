module "inner" {
  source   = "./inner"
  for_each = toset(["x", "y"])
  names    = toset(["n1", "n2"])
}
