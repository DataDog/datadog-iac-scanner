variable "sid_value" {}

data "aws_iam_policy_document" "partial_unknowns" {
  statement {
    effect = "Allow"
    sid    = var.sid_value

    actions = [
      "s3:GetObject",
    ]

    resources = [
      "arn:aws:s3:::my-bucket/*",
    ]
  }
}
