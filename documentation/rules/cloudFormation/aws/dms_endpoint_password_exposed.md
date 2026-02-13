---
title: "DMS endpoint password exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/dms_endpoint_password_exposed"
  id: "5f700072-b7ce-4e84-b3f3-497bf1c24a4d"
  display_name: "DMS endpoint password exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `5f700072-b7ce-4e84-b3f3-497bf1c24a4d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-endpoint.html)

### Description

 Storing AWS DMS endpoint passwords as plaintext in a template or embedding them as a parameter `Default` exposes credentials in source control, CloudFormation templates, and stack metadata. This increases the risk of unauthorized access to database resources.

 For `AWS::DMS::Endpoint` resources, `Properties.Password` must not be a plain string literal or a `Ref` to a `Parameters.<Name>` that defines a `Default` value. Instead, `Password` should reference an AWS Secrets Manager secret or be supplied via a CloudFormation parameter without a `Default` (use `NoEcho` set to `true` to avoid echoing).

 Resources that contain plaintext passwords or parameter references with defaults will be flagged as insecure. Acceptable secure patterns include dynamic Secrets Manager references or parameters provided at deployment time.

Secure examples (CloudFormation YAML):

```yaml
Parameters:
  DbPassword:
    Type: String
    NoEcho: true

MyDmsEndpoint:
  Type: AWS::DMS::Endpoint
  Properties:
    EndpointIdentifier: my-endpoint
    EngineName: mysql
    Username: dbuser
    Password: !Ref DbPassword
```

```yaml
MyDmsEndpoint:
  Type: AWS::DMS::Endpoint
  Properties:
    EndpointIdentifier: my-endpoint
    EngineName: mysql
    Username: dbuser
    Password: "{{resolve:secretsmanager:my-db-secret:SecretString:password}}"
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
  DMSEndpoint1:
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
        MongoDbSettings
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
    "DMSEndpoint3": {
      "Type": "AWS::DMS::Endpoint",
      "Properties": {
        "SslMode": "String",
        "Username": "String",
        "CertificateArn": "String",
        "ExtraConnectionAttributes": "String",
        "KmsKeyId": "String",
        "Password": "{{resolve:secretsmanager:${MyAmpAppSecretManagerRotater}::password}}",
        "Port": 80,
        "EndpointIdentifier": "String",
        "KafkaSettings": "KafkaSettings",
        "KinesisSettings": "KinesisSettings",
        "NeptuneSettings": "NeptuneSettings",
        "S3Settings": "S3Settings",
        "ServerName": "String",
        "Tags": [
          "Tag"
        ],
        "DatabaseName": "String",
        "EndpointType": "String",
        "EngineName": "String",
        "MongoDbSettings": "MongoDbSettings"
      }
    },
    "MyAmpAppSecretManagerRotater": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Description": "This is my amp app instance secret",
        "GenerateSecretString": {
          "SecretStringTemplate": "{\"username\": \"admin\"}",
          "GenerateStringKey": "password",
          "PasswordLength": 16,
          "ExcludeCharacters": "\"@/\\"
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
      "Type": "String",
      "Description": "Password"
    },
    "ParentMasterUsername": {
      "Type": "String",
      "Default": "username",
      "Description": "username"
    }
  },
  "Resources": {
    "DMSEndpoint2": {
      "Type": "AWS::DMS::Endpoint",
      "Properties": {
        "KafkaSettings": "KafkaSettings",
        "NeptuneSettings": "NeptuneSettings",
        "ServerName": "String",
        "Tags": [
          "Tag"
        ],
        "Username": "String",
        "EngineName": "String",
        "DatabaseName": "String",
        "EndpointIdentifier": "String",
        "EndpointType": "String",
        "KinesisSettings": "KinesisSettings",
        "KmsKeyId": "String",
        "Password": "ParentMasterPassword",
        "S3Settings": "S3Settings",
        "CertificateArn": "String",
        "MongoDbSettings": "MongoDbSettings",
        "Port": 80,
        "SslMode": "String",
        "ExtraConnectionAttributes": "String"
      }
    }
  }
}

```
## Non-Compliant Code Examples
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
  DMSEndpoint5:
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
        MongoDbSettings
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

```yaml
Parameters:
  ParentMasterUsername:
    Description: 'username'
    Type: String
    Default: 'username!'
Resources:
  DMSEndpoint6:
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
        MongoDbSettings
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

```json
{
  "Parameters": {
    "ParentMasterPassword": {
      "Description": "Password",
      "Type": "String",
      "Default": "asDjskjs73!"
    },
    "ParentMasterUsername": {
      "Description": "username",
      "Type": "String",
      "Default": "username!"
    }
  },
  "Resources": {
    "DMSEndpoint5": {
      "Type": "AWS::DMS::Endpoint",
      "Properties": {
        "EndpointIdentifier": "String",
        "S3Settings": "S3Settings",
        "ExtraConnectionAttributes": "String",
        "MongoDbSettings": "MongoDbSettings",
        "NeptuneSettings": "NeptuneSettings",
        "Password": "ParentMasterPassword",
        "CertificateArn": "String",
        "EngineName": "String",
        "KinesisSettings": "KinesisSettings",
        "KmsKeyId": "String",
        "ServerName": "String",
        "Username": "String",
        "DatabaseName": "String",
        "EndpointType": "String",
        "KafkaSettings": "KafkaSettings",
        "Port": 80,
        "SslMode": "String",
        "Tags": [
          "Tag"
        ]
      }
    }
  }
}

```