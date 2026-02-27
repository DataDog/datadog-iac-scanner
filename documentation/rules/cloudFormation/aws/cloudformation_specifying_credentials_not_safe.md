---
title: "CloudFormation metadata contains plaintext credentials"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudformation_specifying_credentials_not_safe"
  id: "9ecb6b21-18bc-4aa7-bd07-db20f1c746db"
  display_name: "CloudFormation metadata contains plaintext credentials"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `9ecb6b21-18bc-4aa7-bd07-db20f1c746db`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-authentication.html)

### Description

Embedding plaintext credentials in CloudFormation template metadata exposes secrets to anyone with access to the template or its repository and can lead to credential theft and unauthorized access to resources.

 This rule flags `AWS::EC2::Instance` resources that include an `AWS::CloudFormation::Authentication` metadata block containing inline credentials:

 - For `type: "S3"`, it flags `accessKeyId` or `secretKey`
 - For `type: "basic"`, it flags `password`

 Do not include credential keys in metadata. Instead, grant S3 access via an instance IAM role (`IamInstanceProfile`) and store sensitive values in AWS Secrets Manager or AWS Systems Manager Parameter Store, retrieving them at runtime. 
 
 Secure alternative without embedding credentials:

```yaml
MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    IamInstanceProfile: my-ec2-instance-profile
    # no AWS::CloudFormation::Authentication metadata containing accessKeyId/secretKey/password
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  WebServer:
    Type: AWS::EC2::Instance
    Metadata:
      AWS::CloudFormation::Init:
        config:
          packages:
            yum:
              httpd: []
          files:
            /var/www/html/index.html:
              source:
                Fn::Join:
                  - ""
                  -
                    - "http://s3.amazonaws.com/"
                    - Ref: "BucketName"
                    - "/index.html"
              mode: "000400"
              owner: "apache"
              group: "apache"
              authentication: "S3AccessCreds"
          services:
            sysvinit:
              httpd:
                enabled: "true"
                ensureRunning: "true"

```

```json
{
  "Resources": {
    "WebServer": {
      "Type": "AWS::EC2::Instance",
      "DependsOn": "BucketPolicy",
      "Metadata": {
        "AWS::CloudFormation::Init": {
          "config": {
            "packages": {
              "yum": {
                "httpd": []
              }
            },
            "files": {
              "/var/www/html/index.html": {
                "source": {
                  "Fn::Join": [
                    "",
                    [
                      "http://s3.amazonaws.com/",
                      {
                        "Ref": "BucketName"
                      },
                      "/index.html"
                    ]
                  ]
                },
                "mode": "000400",
                "owner": "apache",
                "group": "apache",
                "authentication": "S3AccessCreds"
              }
            },
            "services": {
              "sysvinit": {
                "httpd": {
                  "enabled": "true",
                  "ensureRunning": "true"
                }
              }
            }
          }
        }
      }
    }
  },
  "Properties": "EC2 Resource Properties ...",
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z"
}

```
## Non-Compliant Code Examples
```json
{
  "Properties": "EC2 Resource Properties ...",
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "WebServer": {
      "DependsOn": "BucketPolicy",
      "Metadata": {
        "AWS::CloudFormation::Init": {
          "config": {
            "packages": {
              "yum": {
                "httpd": []
              }
            },
            "files": {
              "/var/www/html/index.html": {
                "authentication": "S3AccessCreds",
                "source": {
                  "Fn::Join": [
                    "",
                    [
                      "http://s3.amazonaws.com/",
                      {
                        "Ref": "BucketName"
                      },
                      "/index.html"
                    ]
                  ]
                },
                "mode": "000400",
                "owner": "apache",
                "group": "apache"
              }
            },
            "services": {
              "sysvinit": {
                "httpd": {
                  "enabled": "true",
                  "ensureRunning": "true"
                }
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication": {
          "S3AccessCreds": {
            "type": "S3",
            "accessKeyId": {
              "Ref": "CfnKeys"
            },
            "secretKey": {
              "Fn::GetAtt": [
                "CfnKeys",
                "SecretAccessKey"
              ]
            }
          }
        }
      },
      "Type": "AWS::EC2::Instance"
    },
    "WebServer2": {
      "Type": "AWS::EC2::Instance",
      "DependsOn": "BucketPolicy",
      "Metadata": {
        "AWS::CloudFormation::Init": {
          "config": {
            "packages": {
              "yum": {
                "httpd": []
              }
            },
            "files": {
              "/var/www/html/index.html": {
                "group": "apache",
                "authentication": "S3AccessCreds",
                "source": {
                  "Fn::Join": [
                    "",
                    [
                      "http://s3.amazonaws.com/",
                      {
                        "Ref": "BucketName"
                      },
                      "/index.html"
                    ]
                  ]
                },
                "mode": "000400",
                "owner": "apache"
              }
            },
            "services": {
              "sysvinit": {
                "httpd": {
                  "enabled": "true",
                  "ensureRunning": "true"
                }
              }
            }
          }
        },
        "AWS::CloudFormation::Authentication": {
          "BasicAccessCreds": {
            "uris": [
              "example.com/test"
            ],
            "type": "basic",
            "username": {
              "Ref": "UserName"
            },
            "password": {
              "Ref": "Password"
            }
          }
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  WebServer:
    Type: AWS::EC2::Instance
    DependsOn: "BucketPolicy"
    Metadata:
      AWS::CloudFormation::Init:
        config:
          packages:
            yum:
              httpd: []
          files:
            /var/www/html/index.html:
              source:
                Fn::Join:
                  - ""
                  -
                    - "http://s3.amazonaws.com/"
                    - Ref: "BucketName"
                    - "/index.html"
              mode: "000400"
              owner: "apache"
              group: "apache"
              authentication: "S3AccessCreds"
          services:
            sysvinit:
              httpd:
                enabled: "true"
                ensureRunning: "true"
      AWS::CloudFormation::Authentication:
        S3AccessCreds:
          type: "S3"
          accessKeyId:
            Ref: "CfnKeys"
          secretKey:
            Fn::GetAtt:
              - "CfnKeys"
              - "SecretAccessKey"
  WebServer2:
    Type: AWS::EC2::Instance
    DependsOn: "BucketPolicy"
    Metadata:
      AWS::CloudFormation::Init:
        config:
          packages:
            yum:
              httpd: []
          files:
            /var/www/html/index.html:
              source:
                Fn::Join:
                  - ""
                  -
                    - "http://s3.amazonaws.com/"
                    - Ref: "BucketName"
                    - "/index.html"
              mode: "000400"
              owner: "apache"
              group: "apache"
              authentication: "S3AccessCreds"
          services:
            sysvinit:
              httpd:
                enabled: "true"
                ensureRunning: "true"
      AWS::CloudFormation::Authentication:
        BasicAccessCreds:
          type: "basic"
          username:
            Ref: "UserName"
          password:
            Ref: "Password"
          uris:
            - "example.com/test"
Properties:
  EC2 Resource Properties ...
```