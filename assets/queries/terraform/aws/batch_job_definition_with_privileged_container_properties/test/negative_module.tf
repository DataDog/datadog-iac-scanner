module "job_definition" {
  source = "terraform-aws-modules/batch/aws//modules/job-definition"

  container_properties = <<DEFINITION
{
"command": ["ls", "-al", ">", "/tmp/output.txt"],
"image": "busybox",
"jobRoleArn": "arn:aws:iam::111122223333:role/ecsTaskExecutionRole",
"memory": 1024,
"vcpus": 5,
"volumes": [
    {
    "host": {
      "sourcePath": "/tmp"
    },
    "name": "tmp-1"
    }
],
"mountPoints": [
    {
      "containerPath": "/tmp",
      "readOnly": false,
      "sourceVolume": "tmp-1"
    }
],
"privileged": false
}
DEFINITION

  job_definition_name      = "test-job-definition"
  job_definition_type      = "container"
  job_definition_revision  = 1
  job_definition_extension = "json"
  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}