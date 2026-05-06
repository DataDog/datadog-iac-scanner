---
title: "KMS key with vulnerable policy"
group_id: "Ansible / AWS"
meta:
  name: "aws/kms_key_with_full_permissions"
  id: "5b9d237a-57d5-4177-be0e-71434b0fef47"
  display_name: "KMS key with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}5b9d237a-57d5-4177-be0e-71434b0fef47{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/kms_key_module.html)

### Description

KMS key policies that grant broad permissions—such as Allow statements containing `kms:*` or wildcard principals—or that lack conditions can permit unauthorized principals to use, manage, or delete keys. This increases the risk of data exposure or loss.

For Ansible tasks using the `amazon.aws.kms_key` or `aws_kms` modules, inspect the `policy` property. Either omit a custom `policy` so the key uses a safe default, or ensure any provided `policy` does not include `Effect: "Allow"` statements that lack a `Condition` and contain wildcard actions like `kms:*` or wildcard principals (such as `"*"` or account-wide ARNs).

This rule flags KMS resources where a custom `policy` contains an Allow statement without a `Condition` that includes wildcard `kms:*` in `Action` or a wildcard `Principal`. It also flags cases where a custom `policy` is supplied when your organization requires the property to be undefined.

Secure examples — either omit the policy to use safer defaults or supply a restrictive policy that specifies explicit principals, limited actions, and Conditions:

```yaml
- name: Create KMS key using default policy
  amazon.aws.kms_key:
    alias: alias/my-key
    description: "Encryption key for app"
    state: present
```

```yaml
- name: Create KMS key with restricted policy
  amazon.aws.kms_key:
    alias: alias/my-key
    policy:
      Version: "2012-10-17"
      Statement:
        - Sid: "AllowSpecificUse"
          Effect: "Allow"
          Principal:
            AWS: "arn:aws:iam::123456789012:role/MyRole"
          Action:
            - "kms:Encrypt"
            - "kms:Decrypt"
          Resource: "*"
          Condition:
            StringEquals:
              aws:CalledVia: "my-allowed-service.amazonaws.com"
```

## Compliant Code Examples
```yaml
- name: Update IAM policy on an existing KMS key
  amazon.aws.kms_key:
    alias: my-kms-key
    policy: |
      { Id: auto-ebs-2, Statement: [{Action: [kms:Encrypt, kms:Decrypt, kms:ReEncrypt*,
        kms:GenerateDataKey*, kms:CreateGrant, kms:DescribeKey], Condition: {
        StringEquals: {kms:CallerAccount: '111111111111', kms:ViaService: ec2.ap-southeast-2.amazonaws.com}},
        Effect: Allow, Principal: {AWS: '*'}, Resource: '*',
        Sid: Allow access through EBS for all principals in the account that are authorized to use EBS },
      { Action: [kms:Describe*, kms:Get*, kms:List*, kms:RevokeGrant], Effect: Allow,
        Principal: {AWS: arn:aws:iam::111111111111:root}, Resource: '*',
        Sid: Allow direct access to key metadata to the account}], Version: '2012-10-17' }
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: Update IAM policy on an existing KMS key2
  amazon.aws.kms_key:
    alias: my-kms-key
    state: present

```

```yaml
---
- name: Update IAM policy on an existing KMS key
  amazon.aws.kms_key:
    alias: my-kms-key
    policy: {'Id': 'auto-ebs-2', 'Statement': [{'Action': ['kms:*'], 'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Resource': '*', 'Sid': 'Allow access through EBS for all principals in the account that are authorized to use EBS'}, {'Action': ['kms:Describe*', 'kms:Get*', 'kms:List*', 'kms:RevokeGrant'], 'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::111111111111:root'}, 'Resource': '*', 'Sid': 'Allow direct access to key metadata to the account'}], 'Version': '2012-10-17'}
    state: present

```