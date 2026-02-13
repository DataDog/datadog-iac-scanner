module "ecr" {
  source = "terraform-aws-modules/ecr/aws"
  version = "1.2.1"

  repository_name = "my-ecr-repository"
  image_tag_mutability = "IMMUTABLE"

  repository_read_write_access_arns = [
    "arn:aws:iam::0123456789012:role/user1",
    "arn:aws:iam::0123456789012:role/user2"
  ]

  create_lifecycle_policy = true
  repository_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 10
        description  = "Expire images older than 14 days"
        selection    = {
          tagStatus     = "any"
          countType     = "sinceImagePushed"
          countUnit     = "days"
          countNumber   = 14
        }
        action        = {
          type = "expire"
        }
      },
    ]
  })

  tags = {
    Environment = "dev"
    Project     = "foo"
  }
}