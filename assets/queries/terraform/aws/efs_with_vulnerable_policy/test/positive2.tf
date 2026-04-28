resource "aws_efs_file_system_policy" "multi_statement" {
  file_system_id = aws_efs_file_system.example.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SafeStatement",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": ["elasticfilesystem:ClientRead"]
    },
    {
      "Sid": "VulnerableStatement",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["elasticfilesystem:*"]
    }
  ]
}
POLICY
}
