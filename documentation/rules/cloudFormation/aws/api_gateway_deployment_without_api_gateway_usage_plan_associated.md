---
title: "API Gateway deployment without usage plan associated"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_deployment_without_api_gateway_usage_plan_associated"
  id: "783860a3-6dca-4c8b-81d0-7b62769ccbca"
  display_name: "API Gateway deployment without usage plan associated"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `783860a3-6dca-4c8b-81d0-7b62769ccbca`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-deployment.html)

### Description

 API Gateway deployments must be associated with a usage plan to enforce throttling and quotas. This mitigates abuse, denial-of-service risks, and unexpected cost spikes from unbounded API traffic.

 For each `AWS::ApiGateway::Deployment`, there must be an `AWS::ApiGateway::UsagePlan` resource whose `Properties.ApiStages` array contains an entry with:

 - `ApiId` equal to the deployment's `Properties.RestApiId`
 - `Stage` equal to the deployment's `Properties.StageName`

 Resources missing a usage plan or with no `ApiStages` entry matching the deployment's `RestApiId` and `StageName` will be flagged.

Secure configuration example (CloudFormation YAML):

```yaml
MyApi:
  Type: AWS::ApiGateway::RestApi

MyDeployment:
  Type: AWS::ApiGateway::Deployment
  Properties:
    RestApiId: !Ref MyApi
    StageName: prod

MyUsagePlan:
  Type: AWS::ApiGateway::UsagePlan
  Properties:
    UsagePlanName: api-usage-plan
    ApiStages:
      - ApiId: !Ref MyApi
        Stage: prod
    Throttle:
      RateLimit: 100
      BurstLimit: 200
    Quota:
      Limit: 10000
      Period: MONTH
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  Deployment:
    Type: 'AWS::ApiGateway::Deployment'
    Properties:
      RestApiId: !Ref MyRestApi
      Description: My deployment
      StageName: Prod
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
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Router53",
  "Resources": {
    "Deployment": {
      "Type": "AWS::ApiGateway::Deployment",
      "Properties": {
        "RestApiId": "MyRestApi",
        "Description": "My deployment",
        "StageName": "Prod"
      }
    },
    "usagePlan": {
      "Type": "AWS::ApiGateway::UsagePlan",
      "Properties": {
        "ApiStages": [
          {
            "ApiId": "MyRestApi",
            "Stage": "Prod"
          }
        ],
        "Description": "Customer ABC's usage plan",
        "Quota": {
          "Limit": 5000,
          "Period": "MONTH"
        },
        "Throttle": {
          "RateLimit": 100,
          "BurstLimit": 200
        },
        "UsagePlanName": "Plan_ABC"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  Deployment1:
    Type: 'AWS::ApiGateway::Deployment'
    Properties:
      RestApiId: !Ref MyRestApi
      Description: My deployment
      StageName: Prod
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
  Deployment2:
    Type: 'AWS::ApiGateway::Deployment'
    Properties:
      RestApiId: !Ref MyRestApi
      Description: My deployment
      StageName: Prod1
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
    "Deployment1": {
      "Properties": {
        "RestApiId": "MyRestApi",
        "Description": "My deployment",
        "StageName": "Prod"
      },
      "Type": "AWS::ApiGateway::Deployment"
    },
    "usagePlan1": {
      "Properties": {
        "Quota": {
          "Limit": 5000,
          "Period": "MONTH"
        },
        "Throttle": {
          "BurstLimit": 200,
          "RateLimit": 100
        },
        "UsagePlanName": "Plan_ABC",
        "ApiStages": [
          {
            "ApiId": "MyRestApi",
            "Stage": "Prod1"
          }
        ],
        "Description": "Customer ABC's usage plan"
      },
      "Type": "AWS::ApiGateway::UsagePlan"
    }
  }
}

```