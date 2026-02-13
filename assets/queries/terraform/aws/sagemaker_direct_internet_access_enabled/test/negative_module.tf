module "sagemaker_notebook_instance" {
  source = "github.com/SebastianUA/terraform-aws-sagemaker"
  version = "5.3.0"

  notebook_instance_name  = "notebook-instance"
  direct_internet_access  = "Disabled"

  tags = {
    Name        = "My notebook"
    Environment = "Dev"
  }
}
