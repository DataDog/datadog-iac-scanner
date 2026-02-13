module "mq" {
  source = "terraform-aws-modules/mq/aws"
  version = "1.1.0"

  broker_name                = "example"
  engine_type                = "ActiveMQ"
  engine_version             = "5.15.10"
  host_instance_type         = "mq.t3.micro"
  security_group_id_list     = [aws_security_group.allow_mq.id]
  subnet_id                  = "subnet-12345678"
  apply_immediately          = true
  auto_minor_version_upgrade = true
  deployment_mode            = "ACTIVE_STANDBY_MULTI_AZ"

  maintenance_window_start_time = {
    day_of_week = "WEDNESDAY"
    time_of_day = "23:59"
    time_zone   = "UTC"
  }

  logs = {
    general = true
    audit   = true
  }

  user_list = [
    {
      username      = "ExampleUser1"
      password      = "ComplexPassword1"
      console_access = false
      groups         = ["admin"]
    },
    {
      username      = "ExampleUser2"
      password      = "ComplexPassword2"
      console_access = true
    }
  ]
}