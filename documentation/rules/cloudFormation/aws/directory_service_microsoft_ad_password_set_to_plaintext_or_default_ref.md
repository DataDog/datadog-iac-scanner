---
title: "Directory service Microsoft AD password set to plaintext or default ref"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/directory_service_microsoft_ad_password_set_to_plaintext_or_default_ref"
  id: "06b9f52a-8cd5-459b-bdc6-21a22521e1be"
  display_name: "Directory service Microsoft AD password set to plaintext or default ref"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `06b9f52a-8cd5-459b-bdc6-21a22521e1be`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-microsoftad.html)

### Description

 Storing Microsoft AD passwords in plaintext or as a parameter `Default` in CloudFormation exposes credentials to source control, template archives, and other readers. This can enable unauthorized access to the directory and lateral movement across your environment.

 For resources of type `AWS::DirectoryService::MicrosoftAD`, `Properties.Password` must not be a literal string or a `Ref` to a `Parameters.<Name>` that defines a `Default` password.

 Instead, `Password` should reference a secure secret (for example, an AWS Secrets Manager secret or an AWS Systems Manager Parameter Store `SecureString` parameter) or be supplied via a CloudFormation parameter that has no `Default` and uses `NoEcho` set to `true`. This rule flags `Password` values that are plaintext or that point to a parameter with a `Default` value matching a password pattern. Remove parameter defaults containing secrets and prefer Secrets Manager references or parameterized input at deployment time.

Secure examples:

```yaml
MyDirectory:
  Type: AWS::DirectoryService::MicrosoftAD
  Properties:
    Name: corp.example.com
    Password: '{{resolve:secretsmanager:my-secret-id:SecretString:password}}'
    VpcSettings:
      VpcId: vpc-123456
      SubnetIds:
        - subnet-abc
        - subnet-def
```

```yaml
Parameters:
  ADPassword:
    Type: String
    NoEcho: true

MyDirectory:
  Type: AWS::DirectoryService::MicrosoftAD
  Properties:
    Name: corp.example.com
    Password: !Ref ADPassword
    VpcSettings:
      VpcId: vpc-123456
      SubnetIds:
        - subnet-abc
        - subnet-def
```


## Compliant Code Examples
```yaml
Parameters:
  ParentMasterPassword:
    Description: 'Password'
    Type: String
    Default: ''
  ParentMasterUsername:
    Description: 'username'
    Type: String
    Default: 'username!'
Resources:
  NewAmpApp-1:
      Type: AWS::DirectoryService::MicrosoftAD
      Properties:
          CreateAlias: true
          Edition: String
          EnableSso: true
          Name: String
          Password: !Ref ParentMasterPassword
          ShortName: String

```

```json
{
  "Resources": {
    "NewAmpApp-2": {
      "Properties": {
        "CreateAlias": true,
        "Edition": "String",
        "EnableSso": true,
        "Name": "String",
        "Password": "{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::password}}",
        "ShortName": "String"
      },
      "Type": "AWS::DirectoryService::MicrosoftAD"
    },
    "MyAmpAppSecretManagerRotater": {
      "Properties": {
        "Description": "This is my amp app instance secret",
        "GenerateSecretString": {
          "SecretStringTemplate": "{\"username\": \"admin\"}",
          "GenerateStringKey": "password",
          "PasswordLength": 16,
          "ExcludeCharacters": "\"@/\\"
        }
      },
      "Type": "AWS::SecretsManager::Secret"
    }
  }
}

```

```json
{
  "Parameters": {
    "ParentMasterPassword": {
      "Description": "Password",
      "Type": "String"
    },
    "ParentMasterUsername": {
      "Type": "String",
      "Default": "username",
      "Description": "username"
    }
  },
  "Resources": {
    "NewAmpApp-1": {
      "Type": "AWS::DirectoryService::MicrosoftAD",
      "Properties": {
        "CreateAlias": true,
        "Edition": "String",
        "EnableSso": true,
        "Name": "String",
        "Password": "ParentMasterPassword",
        "ShortName": "String"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  NewAmpApp:
      Type: AWS::DirectoryService::MicrosoftAD
      Properties:
          CreateAlias: true
          Edition: String
          EnableSso: true
          Name: String
          Password: 'asDjskjs73!!'
          ShortName: String

```

```yaml
Parameters:
  ParentMasterPassword:
    Description: 'Password'
    Type: String
    Default: 'asDjskjs73!'
  ParentMasterUsername:
    Description: 'username'
    Type: String
    Default: 'username!'
Resources:
  NewAmpApp-1:
      Type: AWS::DirectoryService::MicrosoftAD
      Properties:
          CreateAlias: true
          EnableSso: true
          Edition: String
          Name: String
          Password: !Ref ParentMasterPassword
          ShortName: String


```

```json
{
  "Resources": {
    "NewAmpApp": {
      "Type": "AWS::DirectoryService::MicrosoftAD",
      "Properties": {
        "ShortName": "String",
        "CreateAlias": true,
        "Edition": "String",
        "EnableSso": true,
        "Name": "String",
        "Password": "asDjskjs73!!"
      }
    }
  }
}

```