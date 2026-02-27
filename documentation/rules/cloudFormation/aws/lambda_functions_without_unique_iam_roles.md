---
title: "Lambda functions without unique IAM roles"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/lambda_functions_without_unique_iam_roles"
  id: "ae03f542-1423-402f-9cef-c834e7ee9583"
  display_name: "Lambda functions without unique IAM roles"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ae03f542-1423-402f-9cef-c834e7ee9583`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html)

### Description

Lambda functions must not share the same IAM role because sharing roles expands each function's effective permissions beyond what it needs and increases the blast radius if the role is compromised. This rule inspects `AWS::Lambda::Function` resources and their `Properties.Role`. Each function should reference a distinct IAM role (a unique `AWS::IAM::Role` resource or a unique role ARN). Resources where `Properties.Role` is identical to another function's role will be flagged, including identical ARNs, a `Ref` to the same role resource, or equivalent `Fn::GetAtt` results. To remediate, assign separate IAM role resources per function or narrow policies so roles are not reused across multiple functions.

Secure configuration example (each function has its own role):

```yaml
Function1Role:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

Function1:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: function-1
    Runtime: python3.11
    Role: !GetAtt Function1Role.Arn
    Handler: index.handler
    Code:
      ZipFile: |
        def handler(event, context):
            return {}

Function2Role:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

Function2:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: function-2
    Runtime: python3.11
    Role: !GetAtt Function2Role.Arn
    Handler: index.handler
    Code:
      ZipFile: |
        def handler(event, context):
            return {}
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda function with cfn-response.
Resources:
    Primer01:
        Type: AWS::Lambda::Function
        Properties:
          Runtime: nodejs12.x
          Role: arn:aws:iam::123456789012:role/lambda-role
          Handler: index.handler
          Code:
              ZipFile: |
                var aws = require('aws-sdk')
                var response = require('cfn-response')
                exports.handler = function(event, context) {
                    console.log("REQUEST RECEIVED:\n" + JSON.stringify(event))
                    // For Delete requests, immediately send a SUCCESS response.
                    if (event.RequestType == "Delete") {
                        response.send(event, context, "SUCCESS")
                        return
                    }
                    var responseStatus = "FAILED"
                    var responseData = {}
                    var functionName = event.ResourceProperties.FunctionName
                    var lambda = new aws.Lambda()
                    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {
                        if (err) {
                            responseData = {Error: "Invoke call failed"}
                            console.log(responseData.Error + ":\n", err)
                        }
                        else responseStatus = "SUCCESS"
                        response.send(event, context, responseStatus, responseData)
                    })
                }
          Description: Invoke a function during stack creation.
          TracingConfig:
              Mode: Active
    Primer02:
        Type: AWS::Lambda::Function
        Properties:
          Runtime: nodejs12.x
          Role: arn:aws:iam::123456789012:role/lambda-ex
          Handler: index.handler
          Code:
              ZipFile: |
                var aws = require('aws-sdk')
                var response = require('cfn-response')
                exports.handler = function(event, context) {
                    console.log("REQUEST RECEIVED:\n" + JSON.stringify(event))
                    // For Delete requests, immediately send a SUCCESS response.
                    if (event.RequestType == "Delete") {
                        response.send(event, context, "SUCCESS")
                        return
                    }
                    var responseStatus = "FAILED"
                    var responseData = {}
                    var functionName = event.ResourceProperties.FunctionName
                    var lambda = new aws.Lambda()
                    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {
                        if (err) {
                            responseData = {Error: "Invoke call failed"}
                            console.log(responseData.Error + ":\n", err)
                        }
                        else responseStatus = "SUCCESS"
                        response.send(event, context, responseStatus, responseData)
                    })
                }
          Description: Invoke a function during stack creation.
          TracingConfig:
              Mode: Active
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Lambda function with cfn-response.",
  "Resources": {
    "Primer01": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "index.handler",
        "Code": {
          "ZipFile": "var aws = require('aws-sdk')\nvar response = require('cfn-response')\nexports.handler = function(event, context) {\n    console.log(\"REQUEST RECEIVED:\\n\" + JSON.stringify(event))\n    // For Delete requests, immediately send a SUCCESS response.\n    if (event.RequestType == \"Delete\") {\n        response.send(event, context, \"SUCCESS\")\n        return\n    }\n    var responseStatus = \"FAILED\"\n    var responseData = {}\n    var functionName = event.ResourceProperties.FunctionName\n    var lambda = new aws.Lambda()\n    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {\n        if (err) {\n            responseData = {Error: \"Invoke call failed\"}\n            console.log(responseData.Error + \":\\n\", err)\n        }\n        else responseStatus = \"SUCCESS\"\n        response.send(event, context, responseStatus, responseData)\n    })\n}\n"
        },
        "Description": "Invoke a function during stack creation.",
        "TracingConfig": {
          "Mode": "Active"
        }
      }
    },
    "Primer02": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "TracingConfig": {
          "Mode": "Active"
        },
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-ex",
        "Handler": "index.handler",
        "Code": {
          "ZipFile": "var aws = require('aws-sdk')\nvar response = require('cfn-response')\nexports.handler = function(event, context) {\n    console.log(\"REQUEST RECEIVED:\\n\" + JSON.stringify(event))\n    // For Delete requests, immediately send a SUCCESS response.\n    if (event.RequestType == \"Delete\") {\n        response.send(event, context, \"SUCCESS\")\n        return\n    }\n    var responseStatus = \"FAILED\"\n    var responseData = {}\n    var functionName = event.ResourceProperties.FunctionName\n    var lambda = new aws.Lambda()\n    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {\n        if (err) {\n            responseData = {Error: \"Invoke call failed\"}\n            console.log(responseData.Error + \":\\n\", err)\n        }\n        else responseStatus = \"SUCCESS\"\n        response.send(event, context, responseStatus, responseData)\n    })\n}\n"
        },
        "Description": "Invoke a function during stack creation."
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Lambda function with cfn-response.",
  "Resources": {
    "Primer01": {
      "Properties": {
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "index.handler",
        "Code": {
          "ZipFile": "var aws = require('aws-sdk')\nvar response = require('cfn-response')\nexports.handler = function(event, context) {\n    console.log(\"REQUEST RECEIVED:\\n\" + JSON.stringify(event))\n    // For Delete requests, immediately send a SUCCESS response.\n    if (event.RequestType == \"Delete\") {\n        response.send(event, context, \"SUCCESS\")\n        return\n    }\n    var responseStatus = \"FAILED\"\n    var responseData = {}\n    var functionName = event.ResourceProperties.FunctionName\n    var lambda = new aws.Lambda()\n    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {\n        if (err) {\n            responseData = {Error: \"Invoke call failed\"}\n            console.log(responseData.Error + \":\\n\", err)\n        }\n        else responseStatus = \"SUCCESS\"\n        response.send(event, context, responseStatus, responseData)\n    })\n}\n"
        },
        "Description": "Invoke a function during stack creation.",
        "TracingConfig": {
          "Mode": "Active"
        },
        "Runtime": "nodejs12.x"
      },
      "Type": "AWS::Lambda::Function"
    },
    "Primer02": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "index.handler",
        "Code": {
          "ZipFile": "var aws = require('aws-sdk')\nvar response = require('cfn-response')\nexports.handler = function(event, context) {\n    console.log(\"REQUEST RECEIVED:\\n\" + JSON.stringify(event))\n    // For Delete requests, immediately send a SUCCESS response.\n    if (event.RequestType == \"Delete\") {\n        response.send(event, context, \"SUCCESS\")\n        return\n    }\n    var responseStatus = \"FAILED\"\n    var responseData = {}\n    var functionName = event.ResourceProperties.FunctionName\n    var lambda = new aws.Lambda()\n    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {\n        if (err) {\n            responseData = {Error: \"Invoke call failed\"}\n            console.log(responseData.Error + \":\\n\", err)\n        }\n        else responseStatus = \"SUCCESS\"\n        response.send(event, context, responseStatus, responseData)\n    })\n}\n"
        },
        "Description": "Invoke a function during stack creation.",
        "TracingConfig": {
          "Mode": "Active"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda function with cfn-response.
Resources:
    Primer01:
        Type: AWS::Lambda::Function
        Properties:
          Runtime: nodejs12.x
          Role: arn:aws:iam::123456789012:role/lambda-role
          Handler: index.handler
          Code:
              ZipFile: |
                var aws = require('aws-sdk')
                var response = require('cfn-response')
                exports.handler = function(event, context) {
                    console.log("REQUEST RECEIVED:\n" + JSON.stringify(event))
                    // For Delete requests, immediately send a SUCCESS response.
                    if (event.RequestType == "Delete") {
                        response.send(event, context, "SUCCESS")
                        return
                    }
                    var responseStatus = "FAILED"
                    var responseData = {}
                    var functionName = event.ResourceProperties.FunctionName
                    var lambda = new aws.Lambda()
                    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {
                        if (err) {
                            responseData = {Error: "Invoke call failed"}
                            console.log(responseData.Error + ":\n", err)
                        }
                        else responseStatus = "SUCCESS"
                        response.send(event, context, responseStatus, responseData)
                    })
                }
          Description: Invoke a function during stack creation.
          TracingConfig:
              Mode: Active
    Primer02:
        Type: AWS::Lambda::Function
        Properties:
          Runtime: nodejs12.x
          Role: arn:aws:iam::123456789012:role/lambda-role
          Handler: index.handler
          Code:
              ZipFile: |
                var aws = require('aws-sdk')
                var response = require('cfn-response')
                exports.handler = function(event, context) {
                    console.log("REQUEST RECEIVED:\n" + JSON.stringify(event))
                    // For Delete requests, immediately send a SUCCESS response.
                    if (event.RequestType == "Delete") {
                        response.send(event, context, "SUCCESS")
                        return
                    }
                    var responseStatus = "FAILED"
                    var responseData = {}
                    var functionName = event.ResourceProperties.FunctionName
                    var lambda = new aws.Lambda()
                    lambda.invoke({ FunctionName: functionName }, function(err, invokeResult) {
                        if (err) {
                            responseData = {Error: "Invoke call failed"}
                            console.log(responseData.Error + ":\n", err)
                        }
                        else responseStatus = "SUCCESS"
                        response.send(event, context, responseStatus, responseData)
                    })
                }
          Description: Invoke a function during stack creation.
          TracingConfig:
              Mode: Active
```