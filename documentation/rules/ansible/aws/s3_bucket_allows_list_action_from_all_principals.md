---
title: "S3 Bucket Allows List Action From All Principals"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_allows_list_action_from_all_principals"
  id: "d395a950-12ce-4314-a742-ac5a785ab44e"
  display_name: "S3 Bucket Allows List Action From All Principals"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `d395a950-12ce-4314-a742-ac5a785ab44e`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html)

### Description

S3 bucket policies must not allow List actions to all principals ('*') because exposing bucket listings to everyone reveals object inventories and metadata, enabling data discovery and potential unauthorized access or exfiltration. For Ansible resources using `amazon.aws.s3_bucket` or `s3_bucket`, inspect the bucket `policy` document and ensure there are no policy statements with `Effect` equal to `Allow`, `Principal` equal to `"*"`, and `Action` that includes list operations such as `s3:ListBucket`. Resources with a statement that combines `Effect: Allow`, `Principal: "*"`, and a list action will be flagged; instead restrict access to explicit principals (account IDs, role or service ARNs), apply IAM policies, or use S3 Public Access Block settings to prevent public listing. Secure example policy that grants List only to a specific principal:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListToSpecificPrincipal",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/AllowedRole" },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-bucket"
    }
  ]
}
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    policy:
      Version: '2020-10-07'
      Statement:
      - Effect: Allow
        Action: ListObject
        Principal: NotAll

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    policy:
      Version: "2020-10-07"
      Statement:
      - Effect: Allow
        Action: ListObject
        Principal: "*"

```