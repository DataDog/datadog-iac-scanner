---
title: "API Gateway stage without usage plan associated"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_stage_without_api_gateway_usage_plan_associated"
  id: "7f8f1b60-43df-4c28-aa21-fb836dbd8071"
  display_name: "API Gateway stage without usage plan associated"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `7f8f1b60-43df-4c28-aa21-fb836dbd8071`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html)

### Description

 API Gateway stages must be associated with an API Gateway usage plan to enforce throttling and quota limits and enable API key–based access control. Without a usage plan, a stage is vulnerable to abusive clients, excessive request rates, service exhaustion, and unexpected costs.

 Verify the template includes an `AWS::ApiGateway::UsagePlan` resource and that its `Properties.ApiStages` array contains an entry where:

 - `ApiId` equals the stage's `RestApiId`
 - `Stage` equals the stage's `StageName`

 Resources missing a usage plan or whose usage plan `ApiStages` does not include a matching `ApiId`/`Stage` pair will be flagged. Use intrinsic references so values match, for example:

```yaml
MyApi:
  Type: AWS::ApiGateway::RestApi

MyStage:
  Type: AWS::ApiGateway::Stage
  Properties:
    RestApiId: !Ref MyApi
    StageName: prod

MyUsagePlan:
  Type: AWS::ApiGateway::UsagePlan
  Properties:
    UsagePlanName: MyUsagePlan
    ApiStages:
      - ApiId: !Ref MyApi
        Stage: !Ref MyStage
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
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
  usagePlan:
    Type: 'AWS::ApiGateway::UsagePlan'
    Properties:
      ApiStages:
        - ApiId: !Ref MyRestApi
          Stage: !Ref Prod
      Description: Customer ABC's usage plan
      Quota:
        Limit: 5000
        Period: MONTH
      Throttle:
        BurstLimit: 200
        RateLimit: 100
      UsagePlanName: Plan_ABC



```

```json
{
  "Resources": {
    "Prod": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
        "ClientCertificateId": "ClientCertificate",
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
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "555",
            "ResourcePath": "/stack",
            "HttpMethod": "GET"
          }
        ],
        "StageName": "Prod",
        "Description": "Prod Stage",
        "RestApiId": "MyRestApi",
        "DeploymentId": "TestDeployment",
        "DocumentationVersion": "MyDocumentationVersion"
      }
    },
    "usagePlan": {
      "Type": "AWS::ApiGateway::UsagePlan",
      "Properties": {
        "ApiStages": [
          {
            "Stage": "Prod",
            "ApiId": "MyRestApi"
          }
        ],
        "Description": "Customer ABC's usage plan",
        "Quota": {
          "Period": "MONTH",
          "Limit": 5000
        },
        "Throttle": {
          "BurstLimit": 200,
          "RateLimit": 100
        },
        "UsagePlanName": "Plan_ABC"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Router53"
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  Prod1:
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
  usagePlan1:
    Type: 'AWS::ApiGateway::UsagePlan'
    Properties:
      ApiStages:
        - ApiId: !Ref MyRestApi
          Stage: !Ref Prod1
      Description: Customer ABC's usage plan
      Quota:
        Limit: 5000
        Period: MONTH
      Throttle:
        BurstLimit: 200
        RateLimit: 100
      UsagePlanName: Plan_ABC


```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  Prod2:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi1
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
  usagePlan2:
    Type: 'AWS::ApiGateway::UsagePlan'
    Properties:
      ApiStages:
        - ApiId: !Ref MyRestApi
          Stage: !Ref Prod
      Description: Customer ABC's usage plan
      Quota:
        Limit: 5000
        Period: MONTH
      Throttle:
        BurstLimit: 200
        RateLimit: 100
      UsagePlanName: Plan_ABC








```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Router53",
  "Resources": {
    "Prod1": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
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
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "999",
            "ResourcePath": "/stack",
            "HttpMethod": "POST"
          },
          {
            "ResourcePath": "/stack",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "DataTraceEnabled": "false",
            "ThrottlingBurstLimit": "555"
          }
        ],
        "StageName": "Prod",
        "Description": "Prod Stage",
        "RestApiId": "MyRestApi",
        "DeploymentId": "TestDeployment",
        "DocumentationVersion": "MyDocumentationVersion",
        "ClientCertificateId": "ClientCertificate"
      }
    },
    "usagePlan1": {
      "Type": "AWS::ApiGateway::UsagePlan",
      "Properties": {
        "ApiStages": [
          {
            "ApiId": "MyRestApi",
            "Stage": "Prod1"
          }
        ],
        "Description": "Customer ABC's usage plan",
        "Quota": {
          "Limit": 5000,
          "Period": "MONTH"
        },
        "Throttle": {
          "BurstLimit": 200,
          "RateLimit": 100
        },
        "UsagePlanName": "Plan_ABC"
      }
    }
  }
}

```