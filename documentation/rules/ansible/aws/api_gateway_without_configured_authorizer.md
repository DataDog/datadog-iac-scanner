---
title: "API Gateway without configured authorizer"
group_id: "Ansible / AWS"
meta:
  name: "aws/api_gateway_without_configured_authorizer"
  id: "b16cdb37-ce15-4ab2-8401-d42b05d123fc"
  display_name: "API Gateway without configured authorizer"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b16cdb37-ce15-4ab2-8401-d42b05d123fc`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/api_gateway_module.html)

### Description

API Gateway REST APIs must have an API Gateway authorizer configured so that requests are authenticated before reaching backend integrations. Without an authorizer, APIs can be invoked anonymously, increasing the risk of unauthorized access, data exposure, and abuse of backend services.

For Ansible resources using `community.aws.api_gateway` or `api_gateway`, ensure the API's Swagger/OpenAPI definition—provided via the `swagger_file`, `swagger_dict`, or `swagger_text` property—includes an `x-amazon-apigateway-authorizer` entry in `components.securitySchemes` and that operations reference the authorizer (via `security` at the operation or global level).

Resources that omit all three swagger properties, or whose Swagger/OpenAPI content does not contain `x-amazon-apigateway-authorizer`, are flagged as missing an authorizer. Include a valid authorizer definition and reference it from your paths to remediate the finding.

Secure example with an OpenAPI components authorizer and operation-level security:

```yaml
openapi: "3.0.1"
components:
  securitySchemes:
    MyLambdaAuthorizer:
      x-amazon-apigateway-authorizer:
        type: token
        authorizerUri: arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:MyAuthFunction/invocations
security:
  - MyLambdaAuthorizer: []
paths:
  /resource:
    get:
      security:
        - MyLambdaAuthorizer: []
```

## Compliant Code Examples
```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API definition3
  community.aws.api_gateway:
    name: my-api
    swagger_file: swaggerFile.yaml
    stage: production
    cache_enabled: true
    cache_size: "1.6"
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```

```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API definition22222
  community.aws.api_gateway:
    name: my-api
    swagger_dict:
      {
        "openapi": "3.0.0",
        "info":
          {
            "title": "Simple API Overview",
            "version": "1.0.0",
            "contact": { "name": "contact", "email": "user@gmail.com" },
          },
        "components":
          {
            "securitySchemes":
              {
                "request_authorizer_single_stagevar":
                  {
                    "type": "apiKey",
                    "name": "Unused",
                    "in": "header",
                    "x-amazon-apigateway-authtype": "custom",
                    "x-amazon-apigateway-authorizer":
                      {
                        "type": "request",
                        "identitySource": "stageVariables.stage",
                        "authorizerCredentials": "arn:aws:iam::123456789012:role/AWSepIntegTest-CS-LambdaRole",
                        "authorizerUri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:APIGateway-Request-Authorizer:vtwo/invocations",
                        "authorizerResultTtlInSeconds": 300,
                      },
                  },
              },
          },
      }
    stage: production
    cache_enabled: true
    cache_size: "1.6"
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```

```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API 222
  community.aws.api_gateway:
    name: my-api
    swagger_text: |
      openapi: 3.0.0
      info:
        title: Sample API
        description: Optional multiline or single-line description
        version: 0.1.9
      components:
        securitySchemes:
          request_authorizer_single_stagevar:
            type: apiKey
            name: Unused
            in: header
            x-amazon-apigateway-authtype: custom
            x-amazon-apigateway-authorizer:
              type: request
              identitySource: stageVariables.stage
              authorizerCredentials: arn:aws:iam::123456789012:role/AWSepIntegTest-CS-LambdaRole
              authorizerUri: arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:APIGateway-Request-Authorizer:vtwo/invocations
              authorizerResultTtlInSeconds: 300
          stage: production
    cache_enabled: true
    cache_size: "1.6"
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API definition2
  community.aws.api_gateway:
    name: my-api
    stage: production
    cache_enabled: true
    cache_size: "1.6"
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```

```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API 222
  community.aws.api_gateway:
    name: my-api
    swagger_file: swaggerFileWithoutAuthorizer.yaml
    stage: production
    cache_enabled: true
    cache_size: "1.6"
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```

```yaml
- name: Setup AWS API Gateway setup on AWS and deploy API 222
  community.aws.api_gateway:
    name: my-api
    swagger_text: |
      openapi: 3.0.0
      info:
        title: Sample API
        description: Optional multiline or single-line description
        version: 0.1.9
      components:
        ssecuritySchemes:
          request_authorizer_single_stagevar:
            type: apiKey
            name: Unused
            in: header
            x-amazon-apigateway-authtype: custom
    stage: production
    cache_enabled: true
    cache_size: "1.6"
    tracing_enabled: true
    endpoint_type: EDGE
    state: present

```