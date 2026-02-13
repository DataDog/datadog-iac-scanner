---
title: "API Gateway cache cluster disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_cache_cluster_disabled"
  id: "52790cad-d60d-41d5-8483-146f9f21208d"
  display_name: "API Gateway cache cluster disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `52790cad-d60d-41d5-8483-146f9f21208d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html#cfn-apigateway-stage-cacheclusterenabled)

### Description

API Gateway stages should have cache clustering enabled to reduce repeated backend requests and lower latency, helping prevent backend overload and service degradation. The `CacheClusterEnabled` property on `AWS::ApiGateway::Stage` resources must be defined and set to `true`. Resources missing this property or with `CacheClusterEnabled` set to `false` will be flagged. The `CacheClusterSize` property should also be configured to provision adequate cache capacity for expected traffic.

Secure configuration example:

```yaml
MyStage:
  Type: AWS::ApiGateway::Stage
  Properties:
    StageName: prod
    RestApiId: !Ref MyApi
    CacheClusterEnabled: true
    CacheClusterSize: '0.5'
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
Resources:
  ProdNeg1:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      TracingEnabled: true
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
      CacheClusterEnabled: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "ProdNeg1": {
      "Properties": {
        "CacheClusterEnabled": true,
        "ClientCertificateId": "ClientCertificate",
        "DeploymentId": "TestDeployment",
        "Description": "Prod Stage",
        "DocumentationVersion": "MyDocumentationVersion",
        "MethodSettings": [
          {
            "DataTraceEnabled": "false",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "ResourcePath": "/"
          },
          {
            "DataTraceEnabled": "false",
            "HttpMethod": "POST",
            "MetricsEnabled": "true",
            "ResourcePath": "/stack",
            "ThrottlingBurstLimit": "999"
          },
          {
            "DataTraceEnabled": "false",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "ResourcePath": "/stack",
            "ThrottlingBurstLimit": "555"
          }
        ],
        "RestApiId": "MyRestApi",
        "StageName": "Prod",
        "TracingEnabled": true,
        "Variables": {
          "Stack": "Prod"
        }
      },
      "Type": "AWS::ApiGateway::Stage"
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
Resources:
  ProdPos2:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Prod
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      TracingEnabled: true
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
      CacheClusterEnabled: false

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "ProdPos1": {
      "Type": "AWS::ApiGateway::Stage",
      "Properties": {
        "StageName": "Prod",
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
        "TracingEnabled": "true",
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

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "ProdPos2": {
      "Properties": {
        "CacheClusterEnabled": false,
        "ClientCertificateId": "ClientCertificate",
        "DeploymentId": "TestDeployment",
        "Description": "Prod Stage",
        "DocumentationVersion": "MyDocumentationVersion",
        "MethodSettings": [
          {
            "DataTraceEnabled": "false",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "ResourcePath": "/"
          },
          {
            "DataTraceEnabled": "false",
            "HttpMethod": "POST",
            "MetricsEnabled": "true",
            "ResourcePath": "/stack",
            "ThrottlingBurstLimit": "999"
          },
          {
            "DataTraceEnabled": "false",
            "HttpMethod": "GET",
            "MetricsEnabled": "true",
            "ResourcePath": "/stack",
            "ThrottlingBurstLimit": "555"
          }
        ],
        "RestApiId": "MyRestApi",
        "StageName": "Prod",
        "TracingEnabled": true,
        "Variables": {
          "Stack": "Prod"
        }
      },
      "Type": "AWS::ApiGateway::Stage"
    }
  }
}

```