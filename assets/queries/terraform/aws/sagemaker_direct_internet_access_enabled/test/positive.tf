resource "aws_sagemaker_notebook_instance" "bad_example" {
  name                   = "example-notebook"
  role_arn               = "arn:aws:iam::123456789012:role/SageMakerRole"
  direct_internet_access = "Enabled" # ❌ Direct internet access should be disabled
  instance_type          = "ml.t2.medium"
}
