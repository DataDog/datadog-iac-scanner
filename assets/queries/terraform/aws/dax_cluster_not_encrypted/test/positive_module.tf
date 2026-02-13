module "dax" {
  source = "terraform-aws-modules/dax/aws"
  version = "2.0.0"

  name                   = "cluster"
  server_side_encryption = {}
  iam_role_arn           = "arn:aws:iam::aws_account_id:role/aws_service_role"
  description            = "DAX cluster"
  node_type              = "dax.r4.large"
  replication_factor     = 2

  parameter_group = {
    name        = "default.dax1.0"
    parameters  = [
      {
        name  = "query-ttl-millis"
        value = "100000"
      },
      {
        name  = "record-ttl-millis"
        value = "100000"
      }
    ]
  }

  tags = {
    Environment = "test"
  }
}