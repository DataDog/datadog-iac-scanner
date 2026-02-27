---
title: "CloudWatch metrics disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudwatch_metrics_disabled"
  id: "5d3c1807-acb3-4bb0-be4e-0440230feeaf"
  display_name: "CloudWatch metrics disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `5d3c1807-acb3-4bb0-be4e-0440230feeaf`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cw-alarm.html)

### Description

API Gateway stages must enable CloudWatch metrics for their method settings to provide visibility into request volume, latency, and errors and to support alerting and incident response.

 In CloudFormation, check resources of type `AWS::ApiGateway::Stage`: the `Properties.MethodSettings` array must include `MethodSetting` objects with `MetricsEnabled` set to `true`.

 Resources missing `MethodSettings` or where `MethodSettings[].MetricsEnabled` is missing or set to `false` will be flagged as a security/operational risk. 
 
 Secure configuration example:

```yaml
MyStage:
  Type: AWS::ApiGateway::Stage
  Properties:
    StageName: prod
    RestApiId: !Ref MyApi
    MethodSettings:
      - ResourcePath: "/*"
        HttpMethod: "*"
        MetricsEnabled: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating TestDeployment
Resources:
  Prod:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      Variables:
        Stack: Prod
      MethodSettings:
        - ResourcePath: /
          HttpMethod: GET
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
        - ResourcePath: /stack
          HttpMethod: POST
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
          ThrottlingBurstLimit: '999'
        - ResourcePath: /stack
          HttpMethod: GET
          MetricsEnabled: 'true'
          DataTraceEnabled: 'false'
          ThrottlingBurstLimit: '555'

```

```json
{
  "Resources": {
    "Prod": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
        "StageName": "Prod",
        "Description": "Prod Stage",
        "RestApiId": {
          "Ref": "MyRestApi"
        },
        "DeploymentId": {
          "Ref": "TestDeployment"
        },
        "DocumentationVersion": {
          "Ref": "MyDocumentationVersion"
        },
        "ClientCertificateId": {
          "Ref": "ClientCertificate"
        },
        "Variables": {
          "Stack": "Prod"
        },
        "MethodSettings": [
          {
            "ResourcePath": "/",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "POST",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "999"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "555"
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
    "Prod": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
        "StageName": "Prod",
        "Description": "Prod Stage",
        "RestApiId": {
          "Ref": "MyRestApi"
        },
        "DeploymentId": {
          "Ref": "TestDeployment"
        },
        "DocumentationVersion": {
          "Ref": "MyDocumentationVersion"
        },
        "ClientCertificateId": {
          "Ref": "ClientCertificate"
        },
        "Variables": {
          "Stack": "Prod"
        },
        "MethodSettings": [
          {
            "ResourcePath": "/",
            "HttpMethod": "GET",
            "DataTraceEnabled": "false"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "POST",
            "MetricsEnabled": "false",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "999"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "555"
          }
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating TestDeployment
Resources:
  Prod:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      Variables:
        Stack: Prod

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: Creating TestDeployment
Resources:
  Prod:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      Variables:
        Stack: Prod
      MethodSettings:
        - ResourcePath: /
          HttpMethod: GET
          MetricsEnabled: false
          DataTraceEnabled: false
        - ResourcePath: /stack
          HttpMethod: POST
          DataTraceEnabled: false
          ThrottlingBurstLimit: '999'
        - ResourcePath: /stack
          HttpMethod: GET
          MetricsEnabled: true
          DataTraceEnabled: false
          ThrottlingBurstLimit: '555'

```