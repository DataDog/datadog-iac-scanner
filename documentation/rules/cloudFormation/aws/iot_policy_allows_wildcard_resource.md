---
title: "IoT policy allows a wildcard resource"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iot_policy_allows_wildcard_resource"
  id: "be5b230d-4371-4a28-a441-85dc760e2aa3"
  display_name: "IoT policy allows a wildcard resource"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `be5b230d-4371-4a28-a441-85dc760e2aa3`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iot-policy.html)

### Description

IoT policies must not grant `Allow` permissions to all resources (`*`), because an `Allow` with `Resource: '*'` lets principals act across any IoT resource and can result in broad privilege escalation or unauthorized device and data access. In AWS CloudFormation, check `AWS::IoT::Policy` resources. `Properties.PolicyDocument.Statement[].Effect` must not be `Allow` with the corresponding `Statement[].Resource` equal to or containing the wildcard `*`. The rule flags statements where `Resource` is `*` or an array that includes `*`. Use least-privilege ARNs or condition keys to restrict actions to specific IoT resources.

Secure configuration example:

```yaml
MyIoTPolicy:
  Type: AWS::IoT::Policy
  Properties:
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - "iot:Publish"
          Resource: "arn:aws:iot:us-west-2:123456789012:topic/my/topic"
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
    IoTPolicy:
      Type: AWS::IoT::Policy
      Properties:
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - iot:Connect
            Resource:
            - arn:aws:iot:us-east-1:123456789012:client/client1
        PolicyName: PolicyName

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "IoTPolicy": {
      "Type": "AWS::IoT::Policy",
      "Properties": {
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "iot:Connect"
              ],
              "Resource": [
                "arn:aws:iot:us-east-1:123456789012:client/client1"
              ]
            }
          ]
        },
        "PolicyName": "PolicyName"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Description": "A sample template",
  "Resources": {
    "IoTPolicy": {
      "Type": "AWS::IoT::Policy",
      "Properties": {
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": [
                "iot:Connect"
              ],
              "Resource": "*",
              "Effect": "Allow"
            },
            {
              "Effect": "Deny",
              "Action": [
                "sqs:*"
              ],
              "NotResource": "my-hardcoded-arn"
            }
          ]
        },
        "PolicyName": "PolicyName"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z"
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
    IoTPolicy:
      Type: AWS::IoT::Policy
      Properties:
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - iot:Connect
            Resource: "*"
          - Effect: Deny
            Action:
            - sqs:*
            NotResource: my-hardcoded-arn
        PolicyName: PolicyName

```