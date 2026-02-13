module "dynamodb_table" {
  source  = "terraform-aws-modules/dynamodb-table/aws"
  version = "~> 3.0"

  name     = "game-score"
  hash_key = "UserId"

  attributes = [
    {
      name = "UserId"
      type = "S"
    },
    {
      name = "GameTitle"
      type = "S"
    },
  ]

  global_secondary_indexes = [
    {
      name            = "GameTitleIndex"
      hash_key        = "GameTitle"
      write_capacity  = 10
      read_capacity   = 10
      projection_type = "ALL"
      non_key_attributes = [
        "UserId",
      ]
    },
  ]


  read_capacity  = 1
  write_capacity = 1

  tags = {
    Project     = "GameScore"
    Environment = "dev"
  }
}