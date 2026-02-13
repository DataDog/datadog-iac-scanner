module "eks" {
  source          = "terraform-aws-modules/eks/aws"

  vpc_id = "vpc-1234556abcdef"
  
  encryption_config = {
    resources = ["secrets"]
    provider_key_arn = "aws_eks_cluster.example"
  }
}
