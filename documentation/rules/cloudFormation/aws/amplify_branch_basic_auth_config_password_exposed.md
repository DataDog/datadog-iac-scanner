---
title: "Amplify branch basic auth config password exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/amplify_branch_basic_auth_config_password_exposed"
  id: "dfb56e5d-ee68-446e-b32a-657b62befe69"
  display_name: "Amplify branch basic auth config password exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `dfb56e5d-ee68-446e-b32a-657b62befe69`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-amplify-branch.html#cfn-amplify-branch-basicauthconfig)

### Description

Storing an Amplify branch basic auth password in the template or as a parameter `Default` exposes credentials in source control, template history, and stack artifacts and can allow unauthorized access to your branch.

 This rule checks `AWS::Amplify::Branch` resources where `BasicAuthConfig.EnableBasicAuth` is set to `true`.

 - `BasicAuthConfig.Password` must not be a plain string value.
 - `BasicAuthConfig.Password` must not be a `Ref` to a `Parameters` entry that defines a `Default` containing the secret.

 Instead, store the credential in a secret management service or a secure AWS Systems Manager Parameter Store parameter and reference it from the template. This rule flags `Password` values that look like plaintext passwords (for example, >=`8` characters) or parameter defaults and that are not backed by a Secrets Manager reference. Secure example using a Secrets Manager dynamic reference:

```yaml
MyBranch:
  Type: AWS::Amplify::Branch
  Properties:
    BasicAuthConfig:
      EnableBasicAuth: true
      Username: basic-user
      Password: "{{resolve:secretsmanager:my-secret-id:SecretString:password}}"
```

## Compliant Code Examples
```yaml
Resources:
     NewAmpApp:
        Type: AWS::Amplify::App
        Properties:
          BuildSpec: String
          CustomHeaders: String
          Description: String
          EnableBranchAutoDeletion: true
          IAMServiceRole: String
          Name: NewAmpApp
          OauthToken: String
          Repository: String
          BasicAuthConfig :
            EnableBasicAuth: true
            Password: !Sub '{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::password}}'
            Username: !Sub '{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::username}}'
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
  "Resources": {
    "NewAmpApp4": {
      "Type": "AWS::Amplify::Branch",
      "Properties": {
        "EnableAutoBuild": false,
        "EnablePullRequestPreview": false,
        "EnvironmentVariables": [
          "EnvironmentVariable"
        ],
        "Stage": "String",
        "AppId": "String",
        "BranchName": "String",
        "BuildSpec": "String",
        "Description": "String",
        "BasicAuthConfig": {
          "EnableBasicAuth": true,
          "Password": "ParentPassword",
          "Username": "ParentUsername"
        },
        "EnablePerformanceMode": false,
        "PullRequestEnvironmentName": "String"
      }
    }
  },
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
    "NewAmpApp1": {
      "Type": "AWS::Amplify::Branch",
      "Properties": {
        "AppId": "String",
        "BranchName": "String",
        "EnableAutoBuild": false,
        "EnablePerformanceMode": false,
        "EnablePullRequestPreview": false,
        "BasicAuthConfig": {
          "EnableBasicAuth": true,
          "Password": "ParentPassword",
          "Username": "ParentUsername"
        },
        "BuildSpec": "String",
        "Description": "String",
        "EnvironmentVariables": [
          "EnvironmentVariable"
        ],
        "PullRequestEnvironmentName": "String",
        "Stage": "String"
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
    Default: "@skdsjdk0234!AB"
  ParentUsername:
    Description: 'Username'
    Type: String
    Default: ""
Resources:
  NewAmpApp4:
    Type: AWS::Amplify::Branch
    Properties:
      AppId: String
      BranchName: String
      BuildSpec: String
      Description: String
      EnableAutoBuild: false
      EnablePerformanceMode: false
      EnablePullRequestPreview: false
      EnvironmentVariables:
        - EnvironmentVariable
      PullRequestEnvironmentName: String
      Stage: String
      BasicAuthConfig:
        EnableBasicAuth: true
        Password: !Ref ParentPassword
        Username: !Ref ParentUsername

```

```json
{
  "Resources": {
    "NewAmpApp1": {
      "Type": "AWS::Amplify::Branch",
      "Properties": {
        "BranchName": "String",
        "EnableAutoBuild": false,
        "EnvironmentVariables": [
          "EnvironmentVariable"
        ],
        "PullRequestEnvironmentName": "String",
        "AppId": "String",
        "Description": "String",
        "EnablePerformanceMode": false,
        "EnablePullRequestPreview": false,
        "Stage": "String",
        "BasicAuthConfig": {
          "EnableBasicAuth": true,
          "Password": "@skdsjdk0234!AB",
          "Username": "admin"
        },
        "BuildSpec": "String"
      }
    }
  }
}

```

```json
{
  "Resources": {
    "NewAmpApp4": {
      "Properties": {
        "BasicAuthConfig": {
          "EnableBasicAuth": true,
          "Password": "ParentPassword",
          "Username": "ParentUsername"
        },
        "AppId": "String",
        "Description": "String",
        "EnableAutoBuild": false,
        "EnablePerformanceMode": false,
        "EnablePullRequestPreview": false,
        "EnvironmentVariables": [
          "EnvironmentVariable"
        ],
        "Stage": "String",
        "BranchName": "String",
        "BuildSpec": "String",
        "PullRequestEnvironmentName": "String"
      },
      "Type": "AWS::Amplify::Branch"
    }
  },
  "Parameters": {
    "ParentUsername": {
      "Description": "Username",
      "Type": "String",
      "Default": ""
    },
    "ParentPassword": {
      "Description": "Password",
      "Type": "String",
      "Default": "@skdsjdk0234!AB"
    }
  }
}

```