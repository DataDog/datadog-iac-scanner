module "aws_ami_from_instance_example_2" {
  source = "terraform-aws-modules/ami/aws"
  version = "4.0.1"

  name = "db-ami-%d"

  ebs_block_device {
    device_name           = "/dev/xvda"
    snapshot_description  = "my new snapshot"

    encrypted = false
  }

  depends_on = [aws_ebs_volume.example]
}