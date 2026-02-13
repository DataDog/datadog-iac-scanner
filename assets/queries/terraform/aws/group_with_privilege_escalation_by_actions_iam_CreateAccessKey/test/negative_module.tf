module "group_users" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-group-with-assumable-roles-policy"
  version = "~> 5.2.0"

  name = "developers"

  group_users = [
    "user1",
    "user2"
  ]

  assumable_roles = [
    "arn:aws:iam::835367859851:role/role1",
    "arn:aws:iam::835367859851:role/role2"
  ]

  custom_group_policy = [
    {
      name = "AllowS3Listing"
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Action = [
              "iam:ListUsers",
              "iam:ListRoles"              
            ]
            Effect   = "Allow"
            Resource = "*"
          },
        ]
      })
    },
  ]
}