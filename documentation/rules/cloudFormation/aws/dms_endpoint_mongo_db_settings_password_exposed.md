---
title: "DMS endpoint MongoDB settings password exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/dms_endpoint_mongo_db_settings_password_exposed"
  id: "f988a17f-1139-46a3-8928-f27eafd8b024"
  display_name: "DMS endpoint MongoDB settings password exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `f988a17f-1139-46a3-8928-f27eafd8b024`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-mongodbsettings.html)

### Description

 Storing MongoDB passwords for AWS DMS endpoints in plaintext or as a parameter with a `Default` value exposes credentials in CloudFormation templates, source control, and template outputs. This increases the risk of compromise and unauthorized access.

 Verify the `AWS::DMS::Endpoint` resource's `Properties.MongoDbSettings.Password` is not a literal string value and is not a `Ref` to a `Parameters` entry that defines a `Default`.

 Instead, provide the secret via AWS Secrets Manager (CloudFormation dynamic reference) or as a parameter without a `Default` (and with `NoEcho: true`) so secrets are not embedded in the template. Resources missing a Secrets Manager reference or using parameter defaults will be flagged.

 Secure configuration examples:

```yaml
# Use Secrets Manager dynamic reference
MyDmsEndpoint:
  Type: AWS::DMS::Endpoint
  Properties:
    EndpointIdentifier: my-endpoint
    EngineName: mongodb
    MongoDbSettings:
      Username: myuser
      Password: '{{resolve:secretsmanager:my-secret-id:SecretString:password}}'
```

```yaml
# Use a parameter with NoEcho and no Default
Parameters:
  DbPassword:
    Type: String
    NoEcho: true

MyDmsEndpoint:
  Type: AWS::DMS::Endpoint
  Properties:
    EndpointIdentifier: my-endpoint
    EngineName: mongodb
    MongoDbSettings:
      Username: myuser
      Password: !Ref DbPassword
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
  MasterMongoDBPassword:
    Description: 'Password'
    Type: String
    Default: ''
Resources:
  NewAmpApp1:
    Type: AWS::DMS::Endpoint
    Properties:
      CertificateArn: String
      DatabaseName: String
      EndpointIdentifier: String
      EndpointType: String
      EngineName: String
      ExtraConnectionAttributes: String
      KafkaSettings:
        KafkaSettings
      KinesisSettings:
        KinesisSettings
      KmsKeyId: String
      MongoDbSettings:
          AuthMechanism: String
          AuthSource: String
          AuthType: String
          DatabaseName: String
          DocsToInvestigate: String
          ExtractDocId: String
          NestingLevel: String
          Password: !Ref MasterMongoDBPassword
          Port: 80
          ServerName: String
          Username: String
      NeptuneSettings:
        NeptuneSettings
      Password: !Ref ParentMasterPassword
      Port: 80
      S3Settings:
        S3Settings
      ServerName: String
      SslMode: String
      Tags:
        - Tag
      Username: String

```

```json
{
  "Resources": {
    "MyAmpAppSecretManagerRotater": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Description": "This is my amp app instance secret",
        "GenerateSecretString": {
          "ExcludeCharacters": "\"@/\\",
          "SecretStringTemplate": "{\"username\": \"admin\"}",
          "GenerateStringKey": "password",
          "PasswordLength": 16
        }
      }
    },
    "MongoDBSecretManagerRotater": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Description": "This is my MongoDBSecretManagerRotater instance secret",
        "GenerateSecretString": {
          "GenerateStringKey": "password",
          "PasswordLength": 16,
          "ExcludeCharacters": "\"@/\\",
          "SecretStringTemplate": "{\"username\": \"admin\"}"
        }
      }
    },
    "NewAmpApp3": {
      "Type": "AWS::DMS::Endpoint",
      "Properties": {
        "EndpointType": "String",
        "ExtraConnectionAttributes": "String",
        "KmsKeyId": "String",
        "NeptuneSettings": "NeptuneSettings",
        "CertificateArn": "String",
        "S3Settings": "S3Settings",
        "Username": "String",
        "MongoDbSettings": {
          "Username": "String",
          "AuthMechanism": "String",
          "AuthType": "String",
          "DocsToInvestigate": "String",
          "ExtractDocId": "String",
          "NestingLevel": "String",
          "Password": "{{resolve:secretsmanager:${MongoDBSecretManagerRotater}::password}}",
          "Port": 80,
          "ServerName": "String",
          "AuthSource": "String",
          "DatabaseName": "String"
        },
        "EndpointIdentifier": "String",
        "EngineName": "String",
        "Password": "{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::password}}",
        "Tags": [
          "Tag"
        ],
        "DatabaseName": "String",
        "KinesisSettings": "KinesisSettings",
        "Port": 80,
        "ServerName": "String",
        "SslMode": "String",
        "KafkaSettings": "KafkaSettings"
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
    "MasterMongoDBPassword": {
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
      "Type": "AWS::DMS::Endpoint",
      "Properties": {
        "EngineName": "String",
        "KinesisSettings": "KinesisSettings",
        "Password": "ParentMasterPassword",
        "EndpointIdentifier": "String",
        "KafkaSettings": "KafkaSettings",
        "MongoDbSettings": {
          "AuthMechanism": "String",
          "AuthType": "String",
          "DatabaseName": "String",
          "ExtractDocId": "String",
          "Port": 80,
          "ServerName": "String",
          "AuthSource": "String",
          "DocsToInvestigate": "String",
          "NestingLevel": "String",
          "Password": "MasterMongoDBPassword",
          "Username": "String"
        },
        "Port": 80,
        "CertificateArn": "String",
        "Tags": [
          "Tag"
        ],
        "Username": "String",
        "NeptuneSettings": "NeptuneSettings",
        "S3Settings": "S3Settings",
        "ServerName": "String",
        "SslMode": "String",
        "DatabaseName": "String",
        "EndpointType": "String",
        "ExtraConnectionAttributes": "String",
        "KmsKeyId": "String"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  NewAmpApp5:
    Type: AWS::DMS::Endpoint
    Properties:
      CertificateArn: String
      DatabaseName: String
      EndpointIdentifier: String
      EndpointType: String
      EngineName: String
      ExtraConnectionAttributes: String
      KafkaSettings:
        KafkaSettings
      KinesisSettings:
        KinesisSettings
      KmsKeyId: String
      MongoDbSettings:
          AuthMechanism: String
          AuthSource: String
          AuthType: String
          DatabaseName: String
          DocsToInvestigate: String
          ExtractDocId: String
          NestingLevel: String
          Password: 'as@3djdkDjskjs73!!'
          Port: 80
          ServerName: String
          Username: String
      NeptuneSettings:
        NeptuneSettings
      Password: 'asDjskjs73!!'
      Port: 80
      S3Settings:
        S3Settings
      ServerName: String
      SslMode: String
      Tags:
        - Tag
      Username: String

```

```yaml
Parameters:
  ParentMasterPassword:
    Description: 'Password'
    Type: String
  MasterMongoDBPassword:
    Description: 'Password'
    Type: String
  ParentMasterUsername:
    Description: 'username'
    Type: String
    Default: 'username'
Resources:
  NewAmpApp6:
    Type: AWS::DMS::Endpoint
    Properties:
      CertificateArn: String
      DatabaseName: String
      EndpointIdentifier: String
      EndpointType: String
      EngineName: String
      ExtraConnectionAttributes: String
      KafkaSettings:
        KafkaSettings
      KinesisSettings:
        KinesisSettings
      KmsKeyId: String
      MongoDbSettings:
          AuthMechanism: String
          AuthSource: String
          AuthType: String
          DatabaseName: String
          DocsToInvestigate: String
          ExtractDocId: String
          NestingLevel: String
          Password: 'asDjskjs73!!'
          Port: 80
          ServerName: String
          Username: String
      NeptuneSettings:
        NeptuneSettings
      Password: !Ref ParentMasterPassword
      Port: 80
      S3Settings:
        S3Settings
      ServerName: String
      SslMode: String
      Tags:
        - Tag
      Username: String

```

```json
{
  "Resources": {
    "NewAmpApp5": {
      "Type": "AWS::DMS::Endpoint",
      "Properties": {
        "EndpointIdentifier": "String",
        "EngineName": "String",
        "SslMode": "String",
        "Username": "String",
        "ExtraConnectionAttributes": "String",
        "KafkaSettings": "KafkaSettings",
        "KinesisSettings": "KinesisSettings",
        "NeptuneSettings": "NeptuneSettings",
        "S3Settings": "S3Settings",
        "DatabaseName": "String",
        "MongoDbSettings": {
          "AuthMechanism": "String",
          "AuthSource": "String",
          "AuthType": "String",
          "DatabaseName": "String",
          "Port": 80,
          "Username": "String",
          "DocsToInvestigate": "String",
          "ExtractDocId": "String",
          "NestingLevel": "String",
          "Password": "as@3djdkDjskjs73!!",
          "ServerName": "String"
        },
        "Password": "asDjskjs73!!",
        "ServerName": "String",
        "CertificateArn": "String",
        "EndpointType": "String",
        "KmsKeyId": "String",
        "Port": 80,
        "Tags": [
          "Tag"
        ]
      }
    }
  }
}

```