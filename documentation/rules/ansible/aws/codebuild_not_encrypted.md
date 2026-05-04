---
title: "CodeBuild project is not encrypted"
group_id: "Ansible / AWS"
meta:
  name: "aws/codebuild_not_encrypted"
  id: "ansible-aws-codebuild-not-encrypted"
  display_name: "CodeBuild project is not encrypted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-aws-codebuild-not-encrypted`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/codebuild_project_module.html)

### Description

CodeBuild projects must have a KMS encryption key configured so build artifacts, cached data, and logs are protected at rest.

For Ansible resources using the `community.aws.codebuild_project` or `aws_codebuild` modules, the `encryption_key` property must be defined and set to a valid AWS KMS key ARN or alias (for example `arn:aws:kms:...` or `alias/your-key-alias`). Resources missing `encryption_key` or with it undefined are flagged. 

Example secure task:

```yaml
- name: create codebuild project
  community.aws.codebuild_project:
    name: my-build
    encryption_key: arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-123456ef7890
    # other required properties...
```

## Compliant Code Examples
```yaml
- name: My project v2
  community.aws.codebuild_project:
    name: my-codebuild-project
    description: My nice little project
    service_role: arn:aws:iam::123123:role/service-role/code-build-service-role
    source:
      type: CODEPIPELINE
      buildspec: ''
    artifacts:
      namespaceType: NONE
      packaging: NONE
      type: CODEPIPELINE
      name: my_project
    environment:
      computeType: BUILD_GENERAL1_SMALL
      privilegedMode: 'true'
      image: aws/codebuild/docker:17.09.0
      type: LINUX_CONTAINER
    encryption_key: arn:aws:kms:us-east-1:123123:alias/aws/s3
    region: us-east-1
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: My project
  community.aws.codebuild_project:
    name: my-codebuild-project
    description: My nice little project v2
    service_role: "arn:aws:iam::123123:role/service-role/code-build-service-role"
    source:
      type: CODEPIPELINE
      buildspec: ''
    artifacts:
      namespaceType: NONE
      packaging: NONE
      type: CODEPIPELINE
      name: my_project
    environment:
      computeType: BUILD_GENERAL1_SMALL
      privilegedMode: "true"
      image: "aws/codebuild/docker:17.09.0"
      type: LINUX_CONTAINER
    region: us-east-1
    state: present

```