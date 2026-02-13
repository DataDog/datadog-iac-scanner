module "bucket" {
    source = "./module"
    ip_masked = "127.0.0.1/0"
}
