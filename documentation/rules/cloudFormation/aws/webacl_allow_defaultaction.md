---
title: "Permissive Web ACL default action"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/webacl_allow_defaultaction"
  id: "6d64f311-3da6-45f3-80f1-14db9771ea40"
  display_name: "Permissive Web ACL default action"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `6d64f311-3da6-45f3-80f1-14db9771ea40`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-waf-webacl.html)

### Description

 Setting a Web ACL default action to `ALLOW` causes any request that does not match a rule to be permitted. This can let unhandled or malicious traffic reach your application and undermines the intent of defensive rules.

For `AWS::WAF::WebACL` resources, `Properties.DefaultAction.Type` must not be set to `ALLOW`. It should be set to `BLOCK` to deny requests that do not match allow rules. This rule flags resources where `DefaultAction.Type` is explicitly `ALLOW`. Review such Web ACLs and change the default to `BLOCK` or otherwise ensure rules comprehensively cover allowed traffic.

Secure configuration example:

```yaml
MyWebACL:
  Type: AWS::WAF::WebACL
  Properties:
    Name: my-web-acl
    MetricName: myWebACL
    DefaultAction:
      Type: BLOCK
    Rules: []
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
  MyWebACL:
    Type: "AWS::WAF::WebACL"
    Properties:
      Name: "WebACL to with one rule"
      DefaultAction:
        Type: "BLOCK"
      MetricName: "MyWebACL"
      Rules:
        -
          Action:
            Type: "ALLOW"
          Priority: 1
          RuleId:
            Ref: "MyRule"

```

```json
{
  "Resources": {
    "MyWebACL": {
      "Type": "AWS::WAF::WebACL",
      "Properties": {
        "Name": "WebACL to with one rule",
        "DefaultAction": {
          "Type": "BLOCK"
        },
        "MetricName": "MyWebACL",
        "Rules": [
          {
            "Action": {
              "Type": "ALLOW"
            },
            "Priority": 1,
            "RuleId": {
              "Ref": "MyRule"
            }
          }
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyWebACL": {
      "Type": "AWS::WAF::WebACL",
      "Properties": {
        "Name": "WebACL to with three rules",
        "DefaultAction": {
          "Type": "ALLOW"
        },
        "MetricName": "MyWebACL",
        "Rules": [
          {
            "Action": {
              "Type": "BLOCK"
            },
            "Priority": 1,
            "RuleId": {
              "Ref": "MyRule"
            }
          },
          {
            "RuleId": {
              "Ref": "BadReferersRule"
            },
            "Action": {
              "Type": "BLOCK"
            },
            "Priority": 2
          },
          {
            "RuleId": {
              "Ref": "SqlInjRule"
            },
            "Action": {
              "Type": "BLOCK"
            },
            "Priority": 3
          }
        ]
      }
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
Resources:
  MyWebACL:
    Type: "AWS::WAF::WebACL"
    Properties:
      Name: "WebACL to with three rules"
      DefaultAction:
        Type: "ALLOW"
      MetricName: "MyWebACL"
      Rules:
        -
          Action:
            Type: "BLOCK"
          Priority: 1
          RuleId:
            Ref: "MyRule"
        -
          Action:
            Type: "BLOCK"
          Priority: 2
          RuleId:
            Ref: "BadReferersRule"
        -
          Action:
            Type: "BLOCK"
          Priority: 3
          RuleId:
            Ref: "SqlInjRule"

```