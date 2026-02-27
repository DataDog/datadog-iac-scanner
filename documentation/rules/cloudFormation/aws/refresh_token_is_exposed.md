---
title: "Refresh token is exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/refresh_token_is_exposed"
  id: "5b48c507-0d1f-41b0-a630-76817c6b4189"
  display_name: "Refresh token is exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `5b48c507-0d1f-41b0-a630-76817c6b4189`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ask-skill.html#cfn-ask-skill-authenticationconfiguration)

### Description

Storing an Alexa skill's refresh token as a plaintext value in an AWS CloudFormation template exposes a sensitive credential to source control, CI/CD logs, and anyone with template access. This can enable unauthorized skill access or account compromise. For `Alexa::ASK::Skill` resources, `AuthenticationConfiguration.RefreshToken` must be a string that uses a CloudFormation dynamic reference to a secure store. It should start with `{{resolve:secretsmanager:` or `{{resolve:ssm-secure:`. Resources missing this property, with a non-string value, or with a literal token will be flagged as insecure.

Secure examples using dynamic references:

```yaml
MyAlexaSkillWithSecretsManager:
  Type: Alexa::ASK::Skill
  Properties:
    AuthenticationConfiguration:
      RefreshToken: "{{resolve:secretsmanager:my/alexa/refresh:SecretString:refresh_token}}"
```

```yaml
MyAlexaSkillWithSsm:
  Type: Alexa::ASK::Skill
  Properties:
    AuthenticationConfiguration:
      RefreshToken: "{{resolve:ssm-secure:/alexa/refresh-token:1}}"
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
        S3BucketRole: !GetAtt S3BucketReadRole.Arn
        Overrides:
          Manifest:
            apis:
              custom:
                endpoint:
                  uri: !GetAtt SkillFunction.Arn
      AuthenticationConfiguration:
        ClientId: "amzn1.application-oa2-client.1234"
        ClientSecret: "1234"
        RefreshToken: "{{resolve:secretsmanager:Atzr|IQEBLzAtAhRPpMJxdwVz2Nn6f2y-tpJX2DeX}}"
      VendorId: "1234"
  MySkill2:
    Type: "Alexa::ASK::Skill"
    Properties:
      SkillPackage:
        S3Bucket: "my-skill-packages"
        S3Key: "skillpackage.zip"
        S3BucketRole: !GetAtt S3BucketReadRole.Arn
        Overrides:
          Manifest:
            apis:
              custom:
                endpoint:
                  uri: !GetAtt SkillFunction.Arn
      AuthenticationConfiguration:
        ClientId: "amzn1.application-oa2-client.1234"
        ClientSecret: "1234"
        RefreshToken: "{{resolve:ssm-secure:Atzr|IQEBLzAtAhRPpMJxdwVz2Nn6f2y-tpJX2DeX}}"
      VendorId: "1234"

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
          "S3BucketRole": "S3BucketReadRole.Arn",
          "Overrides": {
            "Manifest": {
              "apis": {
                "custom": {
                  "endpoint": {
                    "uri": "SkillFunction.Arn"
                  }
                }
              }
            }
          }
        },
        "AuthenticationConfiguration": {
          "ClientId": "amzn1.application-oa2-client.1234",
          "ClientSecret": "1234",
          "RefreshToken": "{{resolve:secretsmanager:Atzr|IQEBLzAtAhRPpMJxdwVz2Nn6f2y-tpJX2DeX}}"
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
          "S3BucketRole": "S3BucketReadRole.Arn",
          "Overrides": {
            "Manifest": {
              "apis": {
                "custom": {
                  "endpoint": {
                    "uri": "SkillFunction.Arn"
                  }
                }
              }
            }
          }
        },
        "AuthenticationConfiguration": {
          "ClientId": "amzn1.application-oa2-client.1234",
          "ClientSecret": "1234",
          "RefreshToken": "{{resolve:ssm-secure:Atzr|IQEBLzAtAhRPpMJxdwVz2Nn6f2y-tpJX2DeX}}"
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
        "VendorId": "1234",
        "SkillPackage": {
          "S3Bucket": "my-skill-packages",
          "S3Key": "skillpackage.zip",
          "S3BucketRole": "S3BucketReadRole.Arn",
          "Overrides": {
            "Manifest": {
              "apis": {
                "custom": {
                  "endpoint": {
                    "uri": "SkillFunction.Arn"
                  }
                }
              }
            }
          }
        },
        "AuthenticationConfiguration": {
          "ClientId": "amzn1.application-oa2-client.1234",
          "ClientSecret": "1234",
          "RefreshToken": "Atzr|1234"
        }
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
        S3BucketRole: !GetAtt S3BucketReadRole.Arn
        Overrides:
          Manifest:
            apis:
              custom:
                endpoint:
                  uri: !GetAtt SkillFunction.Arn
      AuthenticationConfiguration:
        ClientId: "amzn1.application-oa2-client.1234"
        ClientSecret: "1234"
        RefreshToken: "Atzr|1234"
      VendorId: "1234"

```