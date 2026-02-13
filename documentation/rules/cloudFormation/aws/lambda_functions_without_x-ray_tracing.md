---
title: "Lambda functions without X-Ray tracing"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/lambda_functions_without_x-ray_tracing"
  id: "9488c451-074e-4cd3-aee3-7db6104f542c"
  display_name: "Lambda functions without X-Ray tracing"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `9488c451-074e-4cd3-aee3-7db6104f542c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-tracingconfig.html)

### Description

 AWS Lambda functions should enable active tracing to capture end-to-end request traces for observability and security investigations. This helps you detect anomalous behavior and perform forensic analysis during incidents. In AWS CloudFormation, `AWS::Lambda::Function` resources must define `TracingConfig.Mode` and set it to `Active`. Resources missing `TracingConfig` or with `TracingConfig.Mode` set to `PassThrough` will be flagged. Also ensure the function execution role permits publishing traces (for example, by attaching the `AWSXRayDaemonWriteAccess` policy).

Secure configuration example:

```yaml
MyFunction:
  Type: AWS::Lambda::Function
  Properties:
    TracingConfig:
      Mode: Active
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda function with cfn-response.
Resources:
  primer:
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

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Lambda function with cfn-response.",
  "Resources": {
    "primer": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "TracingConfig": {
          "Mode": "Active"
        },
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
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
```yaml
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Lambda function with cfn-response.",
  "Resources": {
    "primer": {
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
          "Mode": "PassThrough"
        }
      }
    }
  }
}

```

```json
{
  "Resources": {
    "Function": {
      "Properties": {
        "Timeout": 5,
        "VpcConfig": {
          "SecurityGroupIds": [
            "sg-085912345678492fb"
          ],
          "SubnetIds": [
            "subnet-071f712345678e7c8",
            "subnet-07fd123456788a036"
          ]
        },
        "Handler": "index.handler",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Code": {
          "S3Bucket": "my-bucket",
          "S3Key": "function.zip"
        },
        "Runtime": "nodejs12.x"
      },
      "Type": "AWS::Lambda::Function"
    }
  }
}

```