resource "aws_iam_account_password_policy" "bad_example" {
  minimum_password_length      = 14
  require_symbols              = true
  require_numbers              = false
  require_lowercase_characters = true
  require_uppercase_characters = true
}
