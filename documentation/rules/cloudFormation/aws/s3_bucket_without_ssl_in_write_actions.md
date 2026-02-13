---
title: "S3 bucket without SSL in write actions"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/s3_bucket_without_ssl_in_write_actions"
  id: "38c64e76-c71e-4d92-a337-60174d1de1c9"
  display_name: "S3 bucket without SSL in write actions"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `38c64e76-c71e-4d92-a337-60174d1de1c9`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html)

### Description

 S3 buckets should enforce SSL/TLS for data in transit to prevent unencrypted requests from exposing sensitive data or enabling man-in-the-middle attacks.

Ensure each `AWS::S3::Bucket` has an associated `AWS::S3::BucketPolicy` whose `Properties.PolicyDocument.Statement` enforces `aws:SecureTransport`. For example, use a `Deny` statement that blocks unsafe actions (such as `s3:*` or `s3:PutObject`) when `Condition.Bool["aws:SecureTransport"]` is `false`. Alternatively, use `Allow` statements that only permit those actions when `aws:SecureTransport` is `true`.

Resources missing an `AWS::S3::BucketPolicy`, or with statements that do not include the `Condition.Bool["aws:SecureTransport"]` check (that is, do not deny unsecured requests), will be flagged.

Secure configuration example:

```yaml
MyBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref MyBucket
    PolicyDocument:
      Statement:
        - Sid: EnforceSSL
          Effect: Deny
          Principal: "*"
          Action: "s3:*"
          Resource:
            - !Sub "arn:aws:s3:::${MyBucket}"
            - !Sub "arn:aws:s3:::${MyBucket}/*"
          Condition:
            Bool:
              aws:SecureTransport: "false"
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: S3Bucket
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
    DeletionPolicy: Retain
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Id: MyPolicy
        Version: 2012-10-17
        Statement:
          - Sid: PublicReadForGetBucketObjects
            Effect: Allow
            Principal: '*'
            Action: 's3:GetObject'
            Resource: !Join
              - ''
              - - 'arn:aws:s3:::'
                - !Ref S3Bucket
                - /*
          - Sid: EnsureSSL
            Effect: Deny
            Principal: '*'
            Action: 's3:PutObject'
            Condition:
              Bool:
                'aws:SecureTransport': false
            Resource: !Join
              - ''
              - - 'arn:aws:s3:::'
                - !Ref S3Bucket
                - /*
      Bucket: !Ref S3Bucket
Outputs:
  WebsiteURL:
    Value: !GetAtt
      - S3Bucket
      - WebsiteURL
    Description: URL for website hosted on S3
  S3BucketSecureURL:
    Value: !Join
      - ''
      - - 'https://'
        - !GetAtt
          - S3Bucket
          - DomainName
    Description: Name of S3 bucket to hold website content

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Bucket88:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: S3Bucket88
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
    DeletionPolicy: Retain
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Id: MyPolicy
        Version: 2012-10-17T00:00:00Z
        Statement:
            Effect: Deny
            Principal: '*'
            Action: 's3:*'
            Condition:
              Bool:
                'aws:SecureTransport': false
      Bucket: !Ref S3Bucket88

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Bucket88:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: S3Bucket88
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
    DeletionPolicy: Retain
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Id: MyPolicy
        Version: 2012-10-17T00:00:00Z
        Statement:
            Effect: Allow
            Principal: '*'
            Action: 's3:*'
            Condition:
              Bool:
                'aws:SecureTransport': true
      Bucket: !Ref S3Bucket88

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Bucket2:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: S3Bucket2
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
    DeletionPolicy: Retain
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Id: MyPolicy
        Version: 2012-10-17
        Statement:
          - Sid: EnsureSSL
            Effect: Deny
            Principal: '*'
            Action: 's3:PutObject'
            Condition:
              Bool:
                'aws:SecureTransport': true
            Resource: !Join
              - ''
              - - 'arn:aws:s3:::'
                - !Ref S3Bucket2
                - /*
      Bucket: !Ref S3Bucket2
Outputs:
  WebsiteURL:
    Value: !GetAtt
      - S3Bucket2
      - WebsiteURL
    Description: URL for website hosted on S3
  S3BucketSecureURL:
    Value: !Join
      - ''
      - - 'https://'
        - !GetAtt
          - S3Bucket2
          - DomainName
    Description: Name of S3 bucket to hold website content

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "BucketPolicy": {
      "Properties": {
        "Bucket": "S3Bucket33",
        "PolicyDocument": {
          "Id": "MyPolicy",
          "Statement": {
            "Action": "s3:*",
            "Condition": {
              "Bool": {
                "aws:SecureTransport": false
              }
            },
            "Effect": "Allow",
            "Principal": "*",
            "Resource": [
              "",
              {
                "playbooks": [
                  "arn:aws:s3:::",
                  "S3Bucket3",
                  "/*"
                ]
              }
            ]
          },
          "Version": "2012-10-17"
        }
      },
      "Type": "AWS::S3::BucketPolicy"
    },
    "S3Bucket33": {
      "DeletionPolicy": "Retain",
      "Properties": {
        "BucketName": "S3Bucket33",
        "AccessControl": "PublicRead",
        "WebsiteConfiguration": {
          "ErrorDocument": "error.html",
          "IndexDocument": "index.html"
        }
      },
      "Type": "AWS::S3::Bucket"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Bucket3:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: S3Bucket3
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
    DeletionPolicy: Retain
  S3Bucket4:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: S3Bucket4
      AccessControl: PublicRead
      WebsiteConfiguration:
        IndexDocument: index.html
        ErrorDocument: error.html
    DeletionPolicy: Retain
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Id: MyPolicy
        Version: 2012-10-17
        Statement:
          - Sid: EnsureSSL
            Effect: Allow
            Principal: '*'
            Action: 's3:*'
            Condition:
              Bool:
                'aws:SecureTransport': false
            Resource: !Join
              - ''
              - - 'arn:aws:s3:::'
                - !Ref S3Bucket3
                - /*
      Bucket: !Ref S3Bucket3
Outputs:
  WebsiteURL:
    Value: !GetAtt
      - S3Bucket3
      - WebsiteURL
    Description: URL for website hosted on S3
  S3BucketSecureURL:
    Value: !Join
      - ''
      - - 'https://'
        - !GetAtt
          - S3Bucket3
          - DomainName
    Description: Name of S3 bucket to hold website content

```