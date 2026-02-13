module "mybucket" {
  source = "../"

  bucket_name = "dd-mybucket-eric-aws-simple-test-001"
}

provider "aws" {
  region = "us-west-2"
}
