---
title: "IoT policy allows action as a wildcard"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iot_policy_allows_action_as_wildcard"
  id: "4d32780f-43a4-424a-a06d-943c543576a5"
  display_name: "IoT policy allows action as a wildcard"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `4d32780f-43a4-424a-a06d-943c543576a5`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iot-policy.html)

### Description

 IoT policies that grant the wildcard action `*` with an `Allow` effect are overly permissive and can enable principals to perform any IoT operation. This increases the risk of device takeover, unauthorized message publishing or subscribing, and configuration changes.

In AWS CloudFormation, inspect `AWS::IoT::Policy` resources' `Properties.PolicyDocument.Statement` entries. A `Statement` with `Effect: Allow` and `Action` equal to `*` (or containing `*` in an action array) is a misconfiguration. This rule flags those statements. Follow least privilege by enumerating only the specific `iot:*` actions required and scoping the `Resource` ARNs to the minimum necessary. 

Example secure configuration restricting actions and resources:

```yaml
MyIotPolicy:
  Type: AWS::IoT::Policy
  Properties:
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - "iot:Connect"
            - "iot:Publish"
            - "iot:Subscribe"
            - "iot:Receive"
          Resource: "arn:aws:iot:us-west-2:123456789012:client/my-device-*"
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
  "Resources": {
    "IoTPolicy": {
      "Type": "AWS::IoT::Policy",
      "Properties": {
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": [
                "arn:aws:iot:us-east-1:123456789012:client/client"
              ]
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
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template"
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
            Action: "*"
            Resource:
            - arn:aws:iot:us-east-1:123456789012:client/client
          - Effect: Deny
            Action:
            - sqs:*
            NotResource: my-hardcoded-arn
        PolicyName: PolicyName

```