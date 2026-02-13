module "ecs" {
  source  = "terraform-aws-modules/ecs/aws"
  version = "~> 2.0"

  cluster_name = "my-cluster"

  container_definitions = <<DEFINITION
[
  {
    "name": "ghost",
    "image": "ghost:latest",
    "cpu": 10,
    "memory": 512,
    "essential": true,
    "portMappings": [
      {
        "containerPort": 2368,
        "hostPort": 2368
      }
    ]
  }
]
DEFINITION

  efs_volumes = [
    {
      name = "ghost-content"
      efs_volume_configuration = {
        file_system_id = "fs-12345678"
      }
    }
  ]

  # Task Definitions
  family                = "service"
  cpu                   = 512
  memory                = 512
  network_mode          = "bridge"
  requires_compatibilities = "FARGATE"
  volume {
    name      = "service-storage"
    host_path = "/ecs/service-storage"
  }
}