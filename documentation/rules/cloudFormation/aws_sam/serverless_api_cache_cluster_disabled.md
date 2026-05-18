---
title: "Serverless API cache cluster disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws_sam/serverless_api_cache_cluster_disabled"
  id: "cloudformation-aws-serverless-api-cache-cluster-disabled"
  display_name: "Serverless API cache cluster disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}cloudformation-aws-serverless-api-cache-cluster-disabled{{< /copyable-code >}}

**Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-cacheclusterenabled)

### Description

Amazon API Gateway caching should be enabled for Serverless APIs to reduce backend load and lower latency, helping prevent request amplification that can degrade performance or cause service outages. The `CacheClusterEnabled` property on `AWS::Serverless::Api` resources must be defined and set to `true`. Resources where `CacheClusterEnabled` is missing, `null`, or set to `false` will be flagged. Also consider configuring `CacheClusterSize` to provision adequate cache capacity for your expected traffic.

Secure configuration example:

```yaml
MyApi:
  Type: AWS::Serverless::Api
  Properties:
    StageName: Prod
    CacheClusterEnabled: true
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
      CacheClusterEnabled: true

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
      CacheClusterEnabled: false

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

```