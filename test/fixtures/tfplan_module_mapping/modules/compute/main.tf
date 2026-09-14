variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "instance_tags" {
  description = "Tags for EC2 instances"
  type        = map(string)
  default     = {}
}

resource "aws_instance" "app" {
  ami           = "ami-87654321"
  instance_type = var.instance_type

  # Tags attribute maps to instance_tags variable
  tags = var.instance_tags
}
