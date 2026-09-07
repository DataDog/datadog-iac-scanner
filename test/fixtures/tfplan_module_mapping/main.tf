# Root configuration that uses a module
module "vpc" {
  source = "./modules/networking"

  vpc_cidr = "10.0.0.0/16"

  # This is the module input that maps to the tags attribute
  # Expected finding should point to this line (line 7), not line 2
  resource_tags = {
    Environment = "production"
    Team        = "platform"
  }

  enable_dns_hostnames = true
}

# Another module instance with count
module "app_servers" {
  source = "./modules/compute"
  count  = 3

  instance_type = "t2.micro"

  # Expected finding should point to this line (line 24)
  instance_tags = {
    Environment = "staging"
    Application = "web"
  }
}
