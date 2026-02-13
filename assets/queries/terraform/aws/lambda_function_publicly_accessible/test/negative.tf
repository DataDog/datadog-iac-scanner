resource "aws_lambda_permission" "restricted_lambda" {
  statement_id  = "AllowSpecificAccount"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.my_lambda.function_name
  principal     = "arn:aws:iam::123456789012:root"
}
