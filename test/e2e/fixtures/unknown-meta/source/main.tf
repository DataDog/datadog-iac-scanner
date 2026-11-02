variable "unset" {
  type = string
}

resource "aws_instance" "a" {
  ami = var.unset
}

resource "aws_instance" "b" {
  ami = "ami-1"
}

resource "aws_instance" "c" {
  ami         = "ami-1"
  description = "control"
}
