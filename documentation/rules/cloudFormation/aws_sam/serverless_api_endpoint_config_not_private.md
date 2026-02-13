---
title: "Serverless API endpoint config not private"
group_id: "CloudFormation / AWS"
meta:
  name: "aws_sam/serverless_api_endpoint_config_not_private"
  id: "6b5b0313-771b-4319-ad7a-122ee78700ef"
  display_name: "Serverless API endpoint config not private"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `6b5b0313-771b-4319-ad7a-122ee78700ef`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-endpointconfiguration)

### Description

 Serverless APIs should use a `PRIVATE` endpoint to avoid exposure to the public internet, since public endpoints can allow unauthenticated access and unintended invocation of backend services, leading to data exposure or service abuse. For `AWS::Serverless::Api` resources, the `Properties.EndpointConfiguration.Types` array must be defined and include the value `PRIVATE`. Resources missing `EndpointConfiguration`, missing `Types`, or where `Types` does not contain `PRIVATE` will be flagged.

Secure configuration example:

```yaml
MyApi:
  Type: AWS::Serverless::Api
  Properties:
    StageName: prod
    EndpointConfiguration:
      Types:
        - PRIVATE
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  ApiGatewayApi4:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      TracingEnabled: true
      CacheClusterEnabled: true
      EndpointConfiguration:
        Types:
          - PRIVATE

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  ApiGatewayApi2:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      TracingEnabled: true
      CacheClusterEnabled: true
      EndpointConfiguration:
        VpcEndpointIds:
          - !Ref ApiGatewayVPCEndpoint

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  ApiGatewayApi3:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      TracingEnabled: true
      CacheClusterEnabled: true
      EndpointConfiguration:
        Types:
          - EDGE 

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  ApiGatewayApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      TracingEnabled: true
      CacheClusterEnabled: true

```