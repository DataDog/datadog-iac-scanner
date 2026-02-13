---
title: "Alexa skill plaintext client secret exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/alexa_skill_plaintext_client_secret_exposed"
  id: "3c3b7a58-b018-4d07-9444-d9ee7156e111"
  display_name: "Alexa skill plaintext client secret exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `3c3b7a58-b018-4d07-9444-d9ee7156e111`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ask-skill.html#cfn-ask-skill-authenticationconfiguration)

### Description

Alexa skill client secrets must not be stored as plaintext in CloudFormation templates because embedding secrets in templates exposes credentials to source control and anyone with template access, risking unauthorized access to the skill and its integrations. The `AuthenticationConfiguration.ClientSecret` property on `Alexa::ASK::Skill` resources must be a string that uses a secure dynamic reference beginning with `{{resolve:secretsmanager:` or `{{resolve:ssm-secure:`. This retrieves the secret from AWS Secrets Manager or AWS Systems Manager Parameter Store (`SecureString`) at deploy time. Resources with non-string values or `ClientSecret` values that do not start with those prefixes will be flagged. Use dynamic references instead of hardcoding secrets; for example, a secure CloudFormation configuration looks like:

```yaml
MySkillWithSecretsManager:
  Type: Alexa::ASK::Skill
  Properties:
    AuthenticationConfiguration:
      ClientId: my-client-id
      ClientSecret: "{{resolve:secretsmanager:my-secret-name:SecretString:clientSecret::}}"
```

```yaml
MySkillWithSSM:
  Type: Alexa::ASK::Skill
  Properties:
    AuthenticationConfiguration:
      ClientId: my-client-id
      ClientSecret: "{{resolve:ssm-secure:/my/secure/param:1}}"
```

## Compliant Code Examples
```yaml
Resources:
  MySkill:
    Type: "Alexa::ASK::Skill"
    Properties:
      SkillPackage:
        S3Bucket: "my-skill-packages"
        S3Key: "skillpackage.zip"
        S3BucketRole: arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill
        Overrides:
          Manifest:
            apis:
              custom:
                endpoint:
                  uri: arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill
      AuthenticationConfiguration:
        ClientId: "amzn1.application-oa2-client.1234"
        ClientSecret: "{{resolve:secretsmanager:123456}}"
        RefreshToken: "Atzr|1234"
      VendorId: "1234"
  MySkill2:
    Type: "Alexa::ASK::Skill"
    Properties:
      SkillPackage:
        S3Bucket: "my-skill-packages"
        S3Key: "skillpackage.zip"
        S3BucketRole: arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill
        Overrides:
          Manifest:
            apis:
              custom:
                endpoint:
                  uri: arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill
      AuthenticationConfiguration:
        ClientId: "amzn1.application-oa2-client.1234"
        ClientSecret: "{{resolve:ssm-secure:123456}}"
        RefreshToken: "Atzr|1234"
      VendorId: "1234"
      # trigger validation

```

```json
{
  "Resources": {
    "MySkill": {
      "Type": "Alexa::ASK::Skill",
      "Properties": {
        "SkillPackage": {
          "S3Bucket": "my-skill-packages",
          "S3Key": "skillpackage.zip",
          "S3BucketRole": "arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill",
          "Overrides": {
            "Manifest": {
              "apis": {
                "custom": {
                  "endpoint": {
                    "uri": "arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill"
                  }
                }
              }
            }
          }
        },
        "AuthenticationConfiguration": {
          "ClientId": "amzn1.application-oa2-client.1234",
          "ClientSecret": "{{resolve:secretsmanager:123456}}",
          "RefreshToken": "Atzr|1234"
        },
        "VendorId": "1234"
      }
    },
    "MySkill2": {
      "Type": "Alexa::ASK::Skill",
      "Properties": {
        "SkillPackage": {
          "S3Bucket": "my-skill-packages",
          "S3Key": "skillpackage.zip",
          "S3BucketRole": "arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill",
          "Overrides": {
            "Manifest": {
              "apis": {
                "custom": {
                  "endpoint": {
                    "uri": "arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill"
                  }
                }
              }
            }
          }
        },
        "AuthenticationConfiguration": {
          "ClientId": "amzn1.application-oa2-client.1234",
          "ClientSecret": "{{resolve:ssm-secure:123456}}",
          "RefreshToken": "Atzr|1234"
        },
        "VendorId": "1234"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MySkill": {
      "Type": "Alexa::ASK::Skill",
      "Properties": {
        "SkillPackage": {
          "S3BucketRole": "arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill",
          "Overrides": {
            "Manifest": {
              "apis": {
                "custom": {
                  "endpoint": {
                    "uri": "arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill"
                  }
                }
              }
            }
          },
          "S3Bucket": "my-skill-packages",
          "S3Key": "skillpackage.zip"
        },
        "AuthenticationConfiguration": {
          "ClientId": "amzn1.application-oa2-client.1234",
          "ClientSecret": "1234",
          "RefreshToken": "Atzr|1234"
        },
        "VendorId": "1234"
      }
    }
  }
}

```

```yaml
Resources:
  MySkill:
    Type: "Alexa::ASK::Skill"
    Properties:
      SkillPackage:
        S3Bucket: "my-skill-packages"
        S3Key: "skillpackage.zip"
        S3BucketRole: arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill
        Overrides:
          Manifest:
            apis:
              custom:
                endpoint:
                  uri: arn:aws:lambda:us-east-1:377024778620:function:aws-node-alexa-skill
      AuthenticationConfiguration:
        ClientId: "amzn1.application-oa2-client.1234"
        ClientSecret: "1234"
        RefreshToken: "Atzr|1234"
      VendorId: "1234"

```