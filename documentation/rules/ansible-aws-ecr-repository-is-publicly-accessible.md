---
title: "ECR repository is publicly accessible"
group_id: "Ansible / AWS"
meta:
  name: ""aws/ecr_repository_is_publicly_accessible""
  id: "ansible-aws-ecr-repository-is-publicly-accessible"
  display_name: "ECR repository is publicly accessible"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-ecr-repository-is-publicly-accessible{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ecs_ecr_module.html#parameter-policy)

### Description

ECR repository policies must not grant Allow permissions to the wildcard principal (`*`). This makes repositories publicly accessible and allows unauthorized accounts to pull or push container images, increasing the risk of data exposure and supply-chain compromise.

Check Ansible ECS/ECR tasks using the `community.aws.ecs_ecr` or `ecs_ecr` modules: in the resource `policy` document, any statement with `"Effect": "Allow"` must not have `Principal` equal to `"*"`. Resources with an Allow statement whose `Principal` is `"*"` are flagged. Instead, specify explicit principals such as AWS account ARNs, IAM role ARNs, or service principals, or restrict access using condition keys (for example, `aws:PrincipalOrgID`).

Secure example with an explicit AWS account principal:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": [ "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage" ],
      "Resource": "arn:aws:ecr:us-east-1:123456789012:repository/my-repo"
    }
  ]
}
```

## Compliant Code Examples
```yaml
- name: set-policy as object
  community.aws.ecs_ecr:
    name: needs-policy-object
    policy:
      Version: '2008-10-17'
      Statement:
      - Sid: read-only
        Effect: Allow
        Action:
        - ecr:GetDownloadUrlForLayer
        - ecr:BatchGetImage
        - ecr:BatchCheckLayerAvailability

```
## Non-Compliant Code Examples
```yaml
- name: set-policy as object
  community.aws.ecs_ecr:
    name: needs-policy-object
    policy:
      Version: '2008-10-17'
      Statement:
        - Sid: read-only
          Effect: Allow
          Principal: '*'
          Action:
            - ecr:GetDownloadUrlForLayer
            - ecr:BatchGetImage
            - ecr:BatchCheckLayerAvailability
- name: set-policy as string
  community.aws.ecs_ecr:
    name: needs-policy-string
    policy: >
        {
          "Id": "id113",
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": [
                "s3:put"
              ],
              "Effect": "Allow",
              "Resource": "arn:aws:s3:::S3B_181355/*",
              "Principal": "*"
            }
          ]
        }

```