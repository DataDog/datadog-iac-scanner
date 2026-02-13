module "sns_topic" {
  source = "terraform-aws-modules/sns/aws"
  version = "~> 2.0"

  name  = "my-topic"
  display_name = "My awesome sns topic"

  # We recommend using FIFO topics whenever possible
  fifo_topic = true

  # Use some valid AWS account ID here
  cross_account_iam_role_arns = ["arn:aws:iam::817568760441:role/sns-publish-my-topic"]

  subscriptions = [
    {
      protocol = "lambda"
      endpoint = "arn:aws:lambda:eu-west-1:835367859851:function:example"
    }
  ]

  tags = {
    Name = "my-sns-topic"
  }
  kms_master_key_id = ""
}