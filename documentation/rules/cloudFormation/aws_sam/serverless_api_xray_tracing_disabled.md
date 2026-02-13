---
title: "Serverless API X-Ray tracing disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws_sam/serverless_api_xray_tracing_disabled"
  id: "c757c6a3-ac87-4b9d-b28d-e5a5add6a315"
  display_name: "Serverless API X-Ray tracing disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `c757c6a3-ac87-4b9d-b28d-e5a5add6a315`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-tracingenabled)

### Description

Serverless APIs should have AWS X-Ray tracing enabled to capture distributed traces for requests, which helps diagnose performance issues and investigate security incidents or anomalous application behavior. The `TracingEnabled` property on `AWS::Serverless::Api` resources must be defined and set to `true`. Resources with `TracingEnabled` missing, `null`, or set to `false` will be flagged.

 Secure configuration example:

```yaml
MyServerlessApi:
  Type: AWS::Serverless::Api
  Properties:
    Name: MyApi
    StageName: prod
    TracingEnabled: true
```

## Compliant Code Examples
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
      TracingEnabled: false

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

```