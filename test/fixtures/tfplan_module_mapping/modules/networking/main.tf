variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
}

variable "resource_tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames in VPC"
  type        = bool
  default     = true
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames

  # Tags attribute maps to resource_tags variable
  tags = var.resource_tags
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main.id
  cidr_block = cidrsubnet(var.vpc_cidr, 8, 1)

  # Tags attribute maps to resource_tags variable
  tags = var.resource_tags
}

resource "aws_instance" "bastion" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id

  # Tags attribute maps to resource_tags variable
  tags = var.resource_tags
}
