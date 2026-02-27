---
title: "Serverless API access logging setting undefined"
group_id: "CloudFormation / AWS"
meta:
  name: "aws_sam/serverless_api_access_logging_setting_undefined"
  id: "0a994e04-c6dc-471d-817e-d37451d18a3b"
  display_name: "Serverless API access logging setting undefined"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `0a994e04-c6dc-471d-817e-d37451d18a3b`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-accesslogsetting.html)

### Description

Serverless APIs should have access logging enabled to create an audit trail and support incident investigation and detection of anomalous or abusive traffic. For `AWS::Serverless::Api` resources, the `Properties.AccessLogSetting` property must be defined and not `null`. For `AWS::Serverless::HttpApi` resources, the `Properties.AccessLogSettings` property must be defined and not `null`. These properties configure the log destination and format, so missing or `null` values will be flagged. Ensure the access log configuration includes a log destination (for example, `DestinationArn`) and a `Format` describing the fields to record.

Secure configuration examples:

```yaml
MyServerlessApi:
  Type: AWS::Serverless::Api
  Properties:
    StageName: prod
    AccessLogSetting:
      DestinationArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/my-api-logs
      Format: '$context.identity.sourceIp - $context.requestId - $context.httpMethod $context.path'
```

```yaml
MyHttpApi:
  Type: AWS::Serverless::HttpApi
  Properties:
    AccessLogSettings:
      DestinationArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/my-httpapi-logs
      Format: '{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","method":"$context.httpMethod","path":"$context.path"}'
```

## Compliant Code Examples
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
      AccessLogSetting:
        DestinationArn: 'arn:aws:logs:us-east-1:123456789:log-group:my-log-group'
        Format: >-
          {"requestId":"$context.requestId", "ip": "$context.identity.sourceIp",
          "caller":"$context.identity.caller",
          "user":"$context.identity.user","requestTime":"$context.requestTime",
          "eventType":"$context.eventType","routeKey":"$context.routeKey",
          "status":"$context.status","connectionId":"$context.connectionId"}


```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  HttpApi2:
      Type: AWS::Serverless::HttpApi
      Properties:
        StageName: !Ref StageName
        Tags:
          Tag: Value
        AccessLogSettings:
          DestinationArn: 'arn:aws:logs:us-east-1:123456789:log-group:my-log-group'
          Format: >-
            {"requestId":"$context.requestId", "ip": "$context.identity.sourceIp",
            "caller":"$context.identity.caller",
            "user":"$context.identity.user","requestTime":"$context.requestTime",
            "eventType":"$context.eventType","routeKey":"$context.routeKey",
            "status":"$context.status","connectionId":"$context.connectionId"}



```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  HttpApi:
      Type: AWS::Serverless::HttpApi
      Properties:
        StageName: !Ref StageName
        Tags:
          Tag: Value

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