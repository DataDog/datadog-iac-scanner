module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_version = "1.10"
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  subnets         = ["module.vpc.public_subnets"]
  write_kubeconfig = true

  vpc_id = ""
  cluster_name = ""

  workers_group_defaults = {
    root_volume_size = 100
  }

  worker_groups = [
    {
      instance_type = "m4.large"
      asg_desired_capacity = 2
    }
  ]
}