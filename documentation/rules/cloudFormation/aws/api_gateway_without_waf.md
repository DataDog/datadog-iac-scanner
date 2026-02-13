---
title: "API Gateway without WAF"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/api_gateway_without_waf"
  id: "fcbf9019-566c-4832-a65c-af00d8137d2b"
  display_name: "API Gateway without WAF"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `fcbf9019-566c-4832-a65c-af00d8137d2b`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webaclassociation.html#cfn-wafv2-webaclassociation-resourcearn)

### Description

 API Gateway stages must be protected by a web application firewall (WAF) to block common application-layer attacks such as SQL injection and cross-site scripting, and to reduce the risk of malicious or abusive traffic causing data exposure or service disruption.

 Verify that each `AWS::ApiGateway::Stage` resource (its `StageName`) has a corresponding `AWS::WAFv2::WebACLAssociation` resource. The association must set `Properties.ResourceArn` to the API Gateway stage ARN (format: `arn:aws:apigateway:{region}::/restapis/{restapi-id}/stages/{stageName}`) and must reference a valid WAF via `Properties.WebACLArn`. Resources missing the `AWS::WAFv2::WebACLAssociation`, or whose `ResourceArn` does not reference the stage's `StageName`, will be flagged.

Secure CloudFormation example:

```yaml
MyWebACL:
  Type: AWS::WAFv2::WebACL
  Properties:
    Name: my-webacl
    Scope: REGIONAL
    DefaultAction:
      Allow: {}

MyApi:
  Type: AWS::ApiGateway::RestApi
  Properties:
    Name: my-api

MyStage:
  Type: AWS::ApiGateway::Stage
  Properties:
    StageName: prod
    RestApiId: !Ref MyApi

MyWebACLAssociation:
  Type: AWS::WAFv2::WebACLAssociation
  Properties:
    ResourceArn: !Sub "arn:aws:apigateway:${AWS::Region}::/restapis/${MyApi}/stages/prod"
    WebACLArn: !Ref MyWebACL
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
Resources:
  Production:
    Type: AWS::ApiGateway::Stage
    Properties:
      StageName: Production
      Description: Prod Stage
      RestApiId: !Ref MyRestApi
      DeploymentId: !Ref TestDeployment
      DocumentationVersion: !Ref MyDocumentationVersion
      ClientCertificateId: !Ref ClientCertificate
      Variables:
        Stack: Production
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
  SampleWebACLAssociation:
    Type: 'AWS::WAFv2::WebACLAssociation'
    Properties:
      WebACLArn: ExampleARNForWebACL
      ResourceArn: arn:aws:apigateway:region::/restapis/api-id/stages/Production

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Production": {
      "Properties": {
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
        "StageName": "Production",
        "Variables": {
          "Stack": "Production"
        }
      },
      "Type": "AWS::ApiGateway::Stage"
    },
    "SampleWebACLAssociation": {
      "Properties": {
        "ResourceArn": "arn:aws:apigateway:region::/restapis/api-id/stages/Production",
        "WebACLArn": "ExampleARNForWebACL"
      },
      "Type": "AWS::WAFv2::WebACLAssociation"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Prod": {
      "Properties": {
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
        "Variables": {
          "Stack": "Prod"
        }
      },
      "Type": "AWS::ApiGateway::Stage"
    },
    "SampleWebACLAssociation": {
      "Properties": {
        "ResourceArn": "arn:aws:apigateway:region::/restapis/api-id/stages/stage",
        "WebACLArn": "ExampleARNForWebACL"
      },
      "Type": "AWS::WAFv2::WebACLAssociation"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
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
  SampleWebACLAssociation:
    Type: 'AWS::WAFv2::WebACLAssociation'
    Properties:
      WebACLArn: ExampleARNForWebACL
      ResourceArn: arn:aws:apigateway:region::/restapis/api-id/stages/stage

```