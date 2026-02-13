---
title: "User data contains encoded private key"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/user_data_contains_encoded_private_key"
  id: "568cc372-ca64-420d-9015-ee347d00d288"
  display_name: "User data contains encoded private key"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `568cc372-ca64-420d-9015-ee347d00d288`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html)

### Description

Embedding private keys in instance user data (even if base64-encoded) exposes sensitive credentials that can be decoded and used to gain unauthorized access to instances and pivot within your environment.

For `AWS::AutoScaling::LaunchConfiguration` resources, `Properties.UserData` must not contain PEM private key material. This includes raw PEM headers like `-----BEGIN RSA PRIVATE KEY` or their base64-encoded equivalents. This rule flags `UserData` entries that contain base64 fragments indicative of an encoded PEM header (for example, fragments such as `LS0tLS1CR`) or the raw PEM text.

To remediate, store keys and secrets in a secure service (AWS Secrets Manager, Systems Manager Parameter Store) or provision access via EC2 key pairs, instance roles, or runtime retrieval from a secure store instead of hard-coding them into user data.

Secure configuration example (retrieve secret from Secrets Manager at runtime):

```yaml
MyLaunchConfiguration:
  Type: AWS::AutoScaling::LaunchConfiguration
  Properties:
    ImageId: ami-0abcdef1234567890
    InstanceType: t3.micro
    IamInstanceProfile: !Ref MyInstanceProfile
    UserData:
      Fn::Base64: |
        #!/bin/bash
        aws secretsmanager get-secret-value --secret-id my-app-key --region us-east-1 --query SecretString --output text > /tmp/app-key.pem
        chmod 600 /tmp/app-key.pem
```

## Compliant Code Examples
```yaml
---
Resources:
  myLaunchConfig2:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      ImageId: "ami-02354e95b39ca8dec"
      SecurityGroups:
        - Ref: "myEC2SecurityGroup"
        - myExistingEC2SecurityGroup
      InstanceType: "m1.large"
      KeyName:
        Ref: "KeyName"
      UserData: "some-gibberish"

```

```json
{
  "Resources":{
    "myLaunchConfig":{
      "Type":"AWS::AutoScaling::LaunchConfiguration",
      "Properties":{
        "ImageId":"ami-02354e95b39ca8dec",
        "SecurityGroups":[ { "Ref":"myEC2SecurityGroup" }, "myExistingEC2SecurityGroup" ],
        "InstanceType":"m1.large",
        "KeyName":{
          "Ref":"KeyName"
        },
        "UserData": "some-gibberish"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources":{
    "myLaunchConfig3":{
      "Type":"AWS::AutoScaling::LaunchConfiguration",
      "Properties":{
        "ImageId":"ami-02354e95b39ca8dec",
        "SecurityGroups":[ { "Ref":"myEC2SecurityGroup" }, "myExistingEC2SecurityGroup" ],
        "InstanceType":"m1.large",
        "KeyName":{
          "Ref":"KeyName"
        },
        "UserData": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpzb21lS2V5"
      }
    }
  }
}

```

```yaml
---
Resources:
  myLaunchConfig4:
    Type: AWS::AutoScaling::LaunchConfiguration
    Properties:
      ImageId: "ami-02354e95b39ca8dec"
      SecurityGroups:
        - Ref: "myEC2SecurityGroup"
        - myExistingEC2SecurityGroup
      InstanceType: "m1.large"
      KeyName:
        Ref: "KeyName"
      UserData: "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpzb21lS2V5"

```