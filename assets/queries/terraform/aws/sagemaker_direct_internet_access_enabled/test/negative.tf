resource "aws_sagemaker_notebook_instance" "good_example" {
  name                   = "example-notebook"
  role_arn               = "arn:aws:iam::123456789012:role/SageMakerRole"
  direct_internet_access = "Disabled" # ✅ Direct internet access is correctly disabled
  instance_type          = "ml.t2.medium"
}
