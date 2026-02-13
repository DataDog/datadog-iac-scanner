---
title: "Configuration aggregator to all regions disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/config_configuration_aggregator_to_all_regions_disabled"
  id: "9f3cf08e-72a2-4eb1-8007-e3b1b0e10d4d"
  display_name: "Configuration aggregator to all regions disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `9f3cf08e-72a2-4eb1-8007-e3b1b0e10d4d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configurationaggregator.html)

### Description

 Configuration Aggregators that do not collect data from all AWS Regions create cross-region blind spots, which can lead to incomplete compliance monitoring and limit forensic investigation during incidents.

 For resources of type `AWS::Config::ConfigurationAggregator`, each entry in `AccountAggregationSources` and the `OrganizationAggregationSource` property must include the `AllAwsRegions` attribute set to `true`. Resources that omit aggregation sources, omit the `AllAwsRegions` key, or set `AllAwsRegions` to `false` will be flagged. 
 
 Secure configuration example (CloudFormation YAML):

```yaml
MyConfigAggregator:
  Type: AWS::Config::ConfigurationAggregator
  Properties:
    AccountAggregationSources:
      - AccountIds: ["111111111111"]
        AllAwsRegions: true
    OrganizationAggregationSource:
      RoleArn: arn:aws:iam::111111111111:role/ConfigAggregatorRole
      AllAwsRegions: true
```


## Compliant Code Examples
```yaml
Resources:
  ConfigurationAggregator9:
    Type: 'AWS::Config::ConfigurationAggregator'
    Properties:
      AccountAggregationSources:
        - AccountIds:
            - '123456789012'
            - '987654321012'
          AwsRegions:
            - us-west-2
            - us-east-1
          AllAwsRegions: true
      ConfigurationAggregatorName: MyConfigurationAggregator
  ConfigurationAggregator10:
    Type: 'AWS::Config::ConfigurationAggregator'
    Properties:
      OrganizationAggregationSource:
        RoleArn: >-
          arn:aws:iam::012345678912:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations
        AwsRegions:
          - us-west-2
          - us-east-1
        AllAwsRegions: true
      ConfigurationAggregatorName: MyConfigurationAggregator

```

```json
{
  "Resources": {
    "ConfigurationAggregator6": {
      "Type": "AWS::Config::ConfigurationAggregator",
      "Properties": {
        "AccountAggregationSources": [
          {
            "AccountIds": [
              "123456789012",
              "987654321012"
            ],
            "AwsRegions": [
              "us-west-2",
              "us-east-1"
            ],
            "AllAwsRegions": true
          }
        ],
        "ConfigurationAggregatorName": "MyConfigurationAggregator"
      }
    },
    "ConfigurationAggregator8": {
      "Type": "AWS::Config::ConfigurationAggregator",
      "Properties": {
        "OrganizationAggregationSource": {
          "RoleArn": "arn:aws:iam::012345678912:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations",
          "AwsRegions": [
            "us-west-2",
            "us-east-1"
          ],
          "AllAwsRegions": true
        },
        "ConfigurationAggregatorName": "MyConfigurationAggregator"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "ConfigurationAggregator5": {
      "Type": "AWS::Config::ConfigurationAggregator",
      "Properties": {
        "AccountAggregationSources": [
          {
            "AccountIds": [
              "123456789012",
              "987654321012"
            ],
            "AwsRegions": [
              "us-west-2",
              "us-east-1"
            ]
          }
        ],
        "ConfigurationAggregatorName": "MyConfigurationAggregator"
      }
    },
    "ConfigurationAggregator6": {
      "Type": "AWS::Config::ConfigurationAggregator",
      "Properties": {
        "AccountAggregationSources": [
          {
            "AccountIds": [
              "123456789012",
              "987654321012"
            ],
            "AwsRegions": [
              "us-west-2",
              "us-east-1"
            ],
            "AllAwsRegions": false
          }
        ],
        "ConfigurationAggregatorName": "MyConfigurationAggregator"
      }
    },
    "ConfigurationAggregator7": {
      "Type": "AWS::Config::ConfigurationAggregator",
      "Properties": {
        "OrganizationAggregationSource": {
          "RoleArn": "arn:aws:iam::012345678912:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations",
          "AwsRegions": [
            "us-west-2",
            "us-east-1"
          ]
        },
        "ConfigurationAggregatorName": "MyConfigurationAggregator"
      }
    },
    "ConfigurationAggregator8": {
      "Type": "AWS::Config::ConfigurationAggregator",
      "Properties": {
        "OrganizationAggregationSource": {
          "RoleArn": "arn:aws:iam::012345678912:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations",
          "AwsRegions": [
            "us-west-2",
            "us-east-1"
          ],
          "AllAwsRegions": false
        },
        "ConfigurationAggregatorName": "MyConfigurationAggregator"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OperatorEmail:
    Description: "Email address to notify when new logs are published."
    Type: String
Resources:
  ConfigurationAggregator1:
    Type: 'AWS::Config::ConfigurationAggregator'
    Properties:
      AccountAggregationSources:
        - AccountIds:
            - '123456789012'
            - '987654321012'
          AwsRegions:
            - us-west-2
            - us-east-1
    ConfigurationAggregatorName: MyConfigurationAggregator
  ConfigurationAggregator2:
    Type: 'AWS::Config::ConfigurationAggregator'
    Properties:
      AccountAggregationSources:
        - AccountIds:
            - '123456789012'
            - '987654321012'
          AwsRegions:
            - us-west-2
            - us-east-1
          AllAwsRegions: false
    ConfigurationAggregatorName: MyConfigurationAggregator
  ConfigurationAggregator3:
    Type: 'AWS::Config::ConfigurationAggregator'
    Properties:
      OrganizationAggregationSource:
        RoleArn: >-
          arn:aws:iam::012345678912:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations
        AwsRegions:
          - us-west-2
          - us-east-1
      ConfigurationAggregatorName: MyConfigurationAggregator
  ConfigurationAggregator4:
    Type: 'AWS::Config::ConfigurationAggregator'
    Properties:
      OrganizationAggregationSource:
        RoleArn: >-
          arn:aws:iam::012345678912:role/aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations
        AwsRegions:
          - us-west-2
          - us-east-1
        AllAwsRegions: false
      ConfigurationAggregatorName: MyConfigurationAggregator

```