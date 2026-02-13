---
title: "Directory service simple AD password exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/directory_service_simple_ad_password_exposed"
  id: "6685d912-d81f-4cfa-95ad-e316ea31c989"
  display_name: "Directory service simple AD password exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `6685d912-d81f-4cfa-95ad-e316ea31c989`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-directoryservice-simplead.html)

### Description

 Storing AWS Directory Service Simple AD passwords in plaintext or as parameter `Default` values in CloudFormation exposes directory credentials to anyone who can read the template or parameter defaults. This can enable unauthorized access, lateral movement, and credential leakage via template repositories or build logs.

 For `AWS::DirectoryService::SimpleAD` resources, `Properties.Password` must not be a hard-coded string or a reference to a parameter that defines a `Default` value. Instead, provide the secret via a secrets service or as a parameter with no `Default` so it is supplied at deployment time.

 Resources will be flagged if `Properties.Password` is a literal password string, if it `Ref`s a parameter whose `Parameters.<name>.Default` contains a password-like value, or if the value is not backed by an AWS Secrets Manager or secure parameter reference.

 Secure examples include referencing an AWS Secrets Manager secret via a dynamic reference or using a parameter without a `Default` and supplying the password at deploy time.

Secure dynamic Secrets Manager example:

```yaml
MyDirectory:
  Type: AWS::DirectoryService::SimpleAD
  Properties:
    Name: example.local
    Password: '{{resolve:secretsmanager:my-secret:SecretString:password}}'
    Size: Small
    VpcSettings:
      VpcId: vpc-123456
      SubnetIds:
        - subnet-123456
```

Secure parameter-based example (no Default):

```yaml
Parameters:
  DirectoryPassword:
    Type: String
    NoEcho: true

Resources:
  MyDirectory:
    Type: AWS::DirectoryService::SimpleAD
    Properties:
      Name: example.local
      Password: !Ref DirectoryPassword
      Size: Small
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
  NewAmpApp1:
    Type: AWS::DirectoryService::SimpleAD
    Properties:
        CreateAlias: true
        Description: String
        EnableSso: true
        Name: String
        Password: !Ref ParentMasterPassword
        ShortName: String
        Size: String

```

```json
{
  "Resources": {
    "NewAmpApp3": {
      "Type": "AWS::DirectoryService::SimpleAD",
      "Properties": {
        "Password": "{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::password}}",
        "ShortName": "String",
        "Size": "String",
        "CreateAlias": true,
        "Description": "String",
        "EnableSso": true,
        "Name": "String"
      }
    },
    "MyAmpAppSecretManagerRotater": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Description": "This is my amp app instance secret",
        "GenerateSecretString": {
          "GenerateStringKey": "password",
          "PasswordLength": 16,
          "ExcludeCharacters": "\"@/\\",
          "SecretStringTemplate": "{\"username\": \"admin\"}"
        }
      }
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
      "Description": "username",
      "Type": "String",
      "Default": "username"
    }
  },
  "Resources": {
    "NewAmpApp2": {
      "Type": "AWS::DirectoryService::SimpleAD",
      "Properties": {
        "Size": "String",
        "CreateAlias": true,
        "Description": "String",
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
  NewAmpApp5:
    Type: AWS::DirectoryService::SimpleAD
    Properties:
      CreateAlias: true
      Description: String
      EnableSso: true
      Name: String
      Password: 'asDjskjs73!!'
      ShortName: String
      Size: String

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
  NewAmpApp6:
    Type: AWS::DirectoryService::SimpleAD
    Properties:
      CreateAlias: true
      Description: String
      EnableSso: true
      Name: String
      Password: !Ref ParentMasterPassword
      ShortName: String
      Size: String


```

```json
{
  "Resources": {
    "NewAmpApp5": {
      "Type": "AWS::DirectoryService::SimpleAD",
      "Properties": {
        "ShortName": "String",
        "Size": "String",
        "CreateAlias": true,
        "Description": "String",
        "EnableSso": true,
        "Name": "String",
        "Password": "asDjskjs73!!"
      }
    }
  }
}

```