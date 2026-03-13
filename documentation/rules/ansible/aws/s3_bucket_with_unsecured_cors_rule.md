---
title: "S3 bucket with unsecured CORS rule"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_with_unsecured_cors_rule"
  id: "3505094c-f77c-4ba0-95da-f83db712f86c"
  display_name: "S3 bucket with unsecured CORS rule"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `3505094c-f77c-4ba0-95da-f83db712f86c`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/aws_s3_cors_module.html#parameter-rules)

### Description

S3 CORS rules must restrict allowed origins, methods, and headers to prevent unintended cross-origin access and data exfiltration. Overly permissive CORS (wildcard origins, all methods, or all headers) can allow arbitrary web pages to interact with or read bucket resources.

For Ansible resources `community.aws.aws_s3_cors` and `aws_s3_cors`, inspect each `rules` entry. `allowed_origins` should specify trusted origins (avoid `"*"` or unnecessarily broad lists). `allowed_methods` must not be `["*"]` and should include only the HTTP verbs required by your application. `allowed_headers` must not be `["*"]` and should be limited to the headers actually needed.

Rules with wildcard `allowed_methods` or `allowed_headers`, or with wildcard or overly broad origins are flagged. Prefer a single explicit origin or a narrowly-scoped set and the minimal set of methods and headers.

Secure example:

```yaml
- name: Configure S3 CORS
  community.aws.aws_s3_cors:
    name: my-bucket
    rules:
      - allowed_origins:
          - https://app.example.com
        allowed_methods:
          - GET
          - HEAD
        allowed_headers:
          - Authorization
          - Content-Type
```

## Compliant Code Examples
```yaml
- name: Create s3 bucket
  community.aws.aws_s3_cors:
    name: mys3bucket3
    state: present
    rules:
      - allowed_origins:
          - http://www.example.com/
        allowed_methods:
          - GET
          - POST
        allowed_headers:
          - Authorization
        expose_headers:
          - x-amz-server-side-encryption
          - x-amz-request-id
        max_age_seconds: 30000

```

```yaml
- name: Create s3 bucket1
  aws_s3_cors:
    name: mys3bucket4
    state: present
    rules:
      - allowed_origins:
          - http://www.example.com/
        allowed_methods:
          - GET
          - POST
        allowed_headers:
          - Authorization
        expose_headers:
          - x-amz-server-side-encryption
          - x-amz-request-id
        max_age_seconds: 30000

```
## Non-Compliant Code Examples
```yaml
- name: Create s3 bucket4
  aws_s3_cors:
    name: mys3bucket2
    state: present
    rules:
      - allowed_origins:
          - http://www.example.com/
        allowed_methods:
          - GET
          - POST
          - PUT
          - DELETE
          - HEAD
        allowed_headers:
          - Authorization
        expose_headers:
          - x-amz-server-side-encryption
          - x-amz-request-id
        max_age_seconds: 30000

```

```yaml
- name: Create s3 bucket2
  community.aws.aws_s3_cors:
    name: mys3bucket
    state: present
    rules:
      - allowed_origins:
          - http://www.example.com/
        allowed_methods:
          - GET
          - POST
          - PUT
          - DELETE
          - HEAD
        allowed_headers:
          - Authorization
        expose_headers:
          - x-amz-server-side-encryption
          - x-amz-request-id
        max_age_seconds: 30000

```