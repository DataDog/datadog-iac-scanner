resource "aws_instance" "web_subnet2" {
  ami           = "ami-123456"
  instance_type = "t2.micro"

  tags = merge({
    Name = "${local.resource_prefix.value}-subnet2"
    }, {
    git_last_modified_by = "email@email.com"
    git_modifiers        = "foo.bar"
    git_org              = "checkmarx"
    team                 = "team"
  })
}
