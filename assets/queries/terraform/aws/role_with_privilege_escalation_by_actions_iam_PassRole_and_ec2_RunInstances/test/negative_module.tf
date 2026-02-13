module "role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.1.0"

  create_role = true

  role_name = "custom-role"

  role_policy_arns = {
    custom = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
  }

  trusted_role_services = [
    "ec2.amazonaws.com",
  ]

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
  ]

  number_of_instances = 1

  permissions_boundary = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}