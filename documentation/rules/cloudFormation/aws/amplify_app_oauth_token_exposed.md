---
title: "Amplify app OAuth token exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/amplify_app_oauth_token_exposed"
  id: "03b38885-8f4e-480c-a0e4-12c1affd15db"
  display_name: "Amplify app OAuth token exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `03b38885-8f4e-480c-a0e4-12c1affd15db`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-amplify-app-basicauthconfig.html)

### Description

Amplify app OAuth tokens must not be embedded directly in templates or supplied as parameters with a `Default` value because plaintext or defaulted tokens can be exposed via source control, template snapshots, or CI/CD logs and would allow unauthorized access to linked source repositories and deployment pipelines.

 This rule checks resources of type `AWS::Amplify::App` and the `Properties.OauthToken` value.

 - `OauthToken` must not be a literal token string.
 - `OauthToken` must not be a `Ref`/value that resolves to a parameter which defines a `Default`.

 Instead, supply the token via a secrets service (for example, an AWS Secrets Manager or AWS Systems Manager Parameter Store (`SecureString`) dynamic reference) or via a parameter that has no `Default` and is injected at deploy time.

 This rule flags token-like literal values or parameter references where the referenced `Parameters.<name>.Default` is defined and does not consider Secrets Manager/SSM dynamic references as violations.

Secure examples (CloudFormation YAML):

Using Secrets Manager dynamic reference:

```yaml
MyAmplifyApp:
  Type: AWS::Amplify::App
  Properties:
    Name: my-app
    OauthToken: "{{resolve:secretsmanager:my-secret-id:SecretString:oauth_token}}"
```

Using a Parameter without a Default (supply at deploy time, set NoEcho=true):

```yaml
Parameters:
  GithubTokenParam:
    Type: String
    NoEcho: true

Resources:
  MyAmplifyApp:
    Type: AWS::Amplify::App
    Properties:
      Name: my-app
      OauthToken: !Ref GithubTokenParam
```

## Compliant Code Examples
```yaml
Resources:
     NewAmpApp-2:
        Type: AWS::Amplify::App
        Properties:
          BuildSpec: String
          CustomHeaders: String
          Description: String
          EnableBranchAutoDeletion: true
          IAMServiceRole: String
          Name: NewAmpApp
          Repository: String
          OauthToken: !Sub '{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::password}}'
     MyAmpAppSecretManagerRotater:
        Type: AWS::SecretsManager::Secret
        Properties:
          Description: 'This is my amp app instance secret'
          GenerateSecretString:
            SecretStringTemplate: '{"username": "admin"}'
            GenerateStringKey: 'password'
            PasswordLength: 16
            ExcludeCharacters: '"@/\'

```

```json
{
  "Parameters": {
    "ParentPassword": {
      "Description": "Password",
      "Type": "String",
      "Default": ""
    },
    "ParentUsername": {
      "Description": "Username",
      "Type": "String",
      "Default": ""
    }
  },
  "Resources": {
    "NewAmpApp-4": {
      "Type": "AWS::Amplify::App",
      "Properties": {
        "BuildSpec": "String",
        "CustomHeaders": "String",
        "Description": "String",
        "EnableBranchAutoDeletion": true,
        "IAMServiceRole": "String",
        "Name": "NewAmpApp",
        "Repository": "String",
        "OauthToken": "ParentPassword"
      }
    }
  }
}

```

```json
{
  "Parameters": {
    "ParentPassword": {
      "Description": "Password",
      "Type": "String"
    },
    "ParentUsername": {
      "Description": "Username",
      "Type": "String"
    }
  },
  "Resources": {
    "NewAmpApp-1": {
      "Type": "AWS::Amplify::App",
      "Properties": {
        "BuildSpec": "String",
        "CustomHeaders": "String",
        "Description": "String",
        "EnableBranchAutoDeletion": true,
        "IAMServiceRole": "String",
        "Name": "NewAmpApp",
        "Repository": "String",
        "OauthToken": "ParentPassword"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Parameters:
  ParentPassword:
    Description: 'Password'
    Type: String
    Default: 'CqGZthigPO55H3fi1_6wrP9jmdivueS7lYd7Lg2styBfjsK5eQ5C2qg_gONQgzyvvVojXY0JyMkRdm71y3nTFl1ZYOgJSNLshvWnm9QoEJrInp_xr-o-9RgZHhrGp5X9dCZVYsYF1WHqj5p75O37IKc8Rv6yO9kGw1flCbT4xbeLTDItX71jRzuAHYNKGPKkxrhIuQ-w9MyKYZ0a3pYT4lWZzWVFoMu9G-smC4qrww5grWCUevE9LuNEZgSijFgRK9QPo8PxMt427lGyK-FkoB8x4qllQ1aCG9_mz2t6A1nRxXY7-Jq9ONkmNoUHiTenEUUaPQcz4RFzrkTE-GaUNP_yK2tNR2i5-TQ4tcI8hQW0aaAsWBPoxd_ZXNty9AhRpshU9WUy32yIHj47jMYCpA'
  ParentUsername:
    Description: 'Username'
    Type: String
    Default: ""
Resources:
  NewAmpApp-4:
    Type: AWS::Amplify::App
    Properties:
      BuildSpec: String
      CustomHeaders: String
      Description: String
      EnableBranchAutoDeletion: true
      IAMServiceRole: String
      Name: NewAmpApp
      OauthToken: !Ref ParentPassword
      Repository: String
      BasicAuthConfig:
        EnableBasicAuth: true
        Password: !Ref ParentPassword
        Username: !Ref ParentUsername

```

```json
{
  "Resources": {
    "NewAmpApp-1": {
      "Type": "AWS::Amplify::App",
      "Properties": {
        "Name": "NewAmpApp",
        "Repository": "String",
        "OauthToken": "CqGZthigPO55H3fi1_6wrP9jmdivueS7lYd7Lg2styBfjsK5eQ5C2qg_gONQgzyvvVojXY0JyMkRdm71y3nTFl1ZYOgJSNLshvWnm9QoEJrInp_xr-o-9RgZHhrGp5X9dCZVYsYF1WHqj5p75O37IKc8Rv6yO9kGw1flCbT4xbeLTDItX71jRzuAHYNKGPKkxrhIuQ-w9MyKYZ0a3pYT4lWZzWVFoMu9G-smC4qrww5grWCUevE9LuNEZgSijFgRK9QPo8PxMt427lGyK-FkoB8x4qllQ1aCG9_mz2t6A1nRxXY7-Jq9ONkmNoUHiTenEUUaPQcz4RFzrkTE-GaUNP_yK2tNR2i5-TQ4tcI8hQW0aaAsWBPoxd_ZXNty9AhRpshU9WUy32yIHj47jMYCpA",
        "BuildSpec": "String",
        "CustomHeaders": "String",
        "Description": "String",
        "EnableBranchAutoDeletion": true,
        "IAMServiceRole": "String"
      }
    }
  }
}

```

```json
{
  "Parameters": {
    "ParentUsername": {
      "Description": "Username",
      "Type": "String",
      "Default": ""
    },
    "ParentPassword": {
      "Description": "Password",
      "Type": "String",
      "Default": "CqGZthigPO55H3fi1_6wrP9jmdivueS7lYd7Lg2styBfjsK5eQ5C2qg_gONQgzyvvVojXY0JyMkRdm71y3nTFl1ZYOgJSNLshvWnm9QoEJrInp_xr-o-9RgZHhrGp5X9dCZVYsYF1WHqj5p75O37IKc8Rv6yO9kGw1flCbT4xbeLTDItX71jRzuAHYNKGPKkxrhIuQ-w9MyKYZ0a3pYT4lWZzWVFoMu9G-smC4qrww5grWCUevE9LuNEZgSijFgRK9QPo8PxMt427lGyK-FkoB8x4qllQ1aCG9_mz2t6A1nRxXY7-Jq9ONkmNoUHiTenEUUaPQcz4RFzrkTE-GaUNP_yK2tNR2i5-TQ4tcI8hQW0aaAsWBPoxd_ZXNty9AhRpshU9WUy32yIHj47jMYCpA"
    }
  },
  "Resources": {
    "NewAmpApp-4": {
      "Type": "AWS::Amplify::App",
      "Properties": {
        "Repository": "String",
        "BasicAuthConfig": {
          "EnableBasicAuth": true,
          "Password": "ParentPassword",
          "Username": "ParentUsername"
        },
        "OauthToken": "ParentPassword",
        "BuildSpec": "String",
        "CustomHeaders": "String",
        "Description": "String",
        "EnableBranchAutoDeletion": true,
        "IAMServiceRole": "String",
        "Name": "NewAmpApp"
      }
    }
  }
}

```