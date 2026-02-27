---
title: "EMR cluster without security configuration"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/emr_cluster_without_security_configuration"
  id: "48af92a5-c89b-4936-bc62-1086fe2bab23"
  display_name: "EMR cluster without security configuration"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `48af92a5-c89b-4936-bc62-1086fe2bab23`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticmapreduce-cluster.html#cfn-elasticmapreduce-cluster-securityconfiguration)

### Description

EMR clusters must reference an EMR security configuration so cluster-level security settings (such as encryption and authentication controls) are applied. Without a security configuration, data at rest or in transit and access controls may not be enforced, increasing the risk of data exposure or unauthorized access.
 
 In CloudFormation, the `SecurityConfiguration` property on `AWS::EMR::Cluster` must be defined and set to the logical name (string) of a resource of type `AWS::EMR::SecurityConfiguration`. Resources missing this property, or where the `SecurityConfiguration` value does not match an `AWS::EMR::SecurityConfiguration` resource in the same template, will be flagged. 
 
 Secure configuration example:

```yaml
EMRSecurityConfig:
  Type: AWS::EMR::SecurityConfiguration
  Properties:
    Name: my-emr-security-config
    SecurityConfiguration: |
      {
        "EncryptionConfiguration": { "EnableAtRestEncryption": true }
      }

EMRCluster:
  Type: AWS::EMR::Cluster
  Properties:
    Name: my-emr-cluster
    ReleaseLabel: emr-6.3.0
    Instances: {}
    SecurityConfiguration: !Ref EMRSecurityConfig
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  CrossRealmTrustPrincipalPassword:
    Type: String
  KdcAdminPassword:
    Type: String
  Realm:
    Type: String
  InstanceType:
    Type: String
  ReleaseLabel:
    Type: String
  SubnetId:
    Type: String
Resources:
  cluster:
    Type: 'AWS::EMR::Cluster'
    Properties:
      Instances:
        MasterInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnMaster
        CoreInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnCore
        Ec2SubnetId: !Ref SubnetId
      Name: CFNtest2
      JobFlowRole: !Ref emrEc2InstanceProfile
      KerberosAttributes:
        CrossRealmTrustPrincipalPassword: CfnIntegrationTest-1
        KdcAdminPassword: CfnIntegrationTest-1
        Realm: EC2.INTERNAL
      ServiceRole: !Ref emrRole
      ReleaseLabel: !Ref ReleaseLabel
      SecurityConfiguration: !Ref securityConfiguration
      VisibleToAllUsers: true
      Tags:
        - Key: key1
          Value: value1
  key:
    Type: 'AWS::KMS::Key'
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !GetAtt
                - emrEc2Role
                - Arn
            Action: 'kms:*'
            Resource: '*'
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Join
                - ''
                - - 'arn:aws:iam::'
                  - !Ref 'AWS::AccountId'
                  - ':root'
            Action: 'kms:*'
            Resource: '*'
  securityConfiguration:
    Type: 'AWS::EMR::SecurityConfiguration'
    Properties:
      SecurityConfiguration:
        AuthenticationConfiguration:
          KerberosConfiguration:
            Provider: ClusterDedicatedKdc
            ClusterDedicatedKdcConfiguration:
              TicketLifetimeInHours: 24
              CrossRealmTrustConfiguration:
                Realm: AD.DOMAIN.COM
                Domain: ad.domain.com
                AdminServer: ad.domain.com
                KdcServer: ad.domain.com
  emrRole:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: elasticmapreduce.amazonaws.com
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole'
  emrEc2Role:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role'
  emrEc2InstanceProfile:
    Type: 'AWS::IAM::InstanceProfile'
    Properties:
      Path: /
      Roles:
        - !Ref emrEc2Role
Outputs:
  keyArn:
    Value: !GetAtt
      - key
      - Arn

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Parameters": {
    "CrossRealmTrustPrincipalPassword": {
      "Type": "String"
    },
    "KdcAdminPassword": {
      "Type": "String"
    },
    "Realm": {
      "Type": "String"
    },
    "InstanceType": {
      "Type": "String"
    },
    "ReleaseLabel": {
      "Type": "String"
    },
    "SubnetId": {
      "Type": "String"
    }
  },
  "Resources": {
    "emrEc2Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "ec2.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
        ]
      }
    },
    "emrEc2InstanceProfile": {
      "Properties": {
        "Path": "/",
        "Roles": [
          "emrEc2Role"
        ]
      },
      "Type": "AWS::IAM::InstanceProfile"
    },
    "cluster": {
      "Type": "AWS::EMR::Cluster",
      "Properties": {
        "Name": "CFNtest2",
        "JobFlowRole": "emrEc2InstanceProfile",
        "ServiceRole": "emrRole",
        "SecurityConfiguration": "securityConfiguration",
        "Tags": [
          {
            "Key": "key1",
            "Value": "value1"
          }
        ],
        "Instances": {
          "MasterInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": "InstanceType",
            "Market": "ON_DEMAND",
            "Name": "cfnMaster"
          },
          "CoreInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": "InstanceType",
            "Market": "ON_DEMAND",
            "Name": "cfnCore"
          },
          "Ec2SubnetId": "SubnetId"
        },
        "KerberosAttributes": {
          "CrossRealmTrustPrincipalPassword": "CfnIntegrationTest-1",
          "KdcAdminPassword": "CfnIntegrationTest-1",
          "Realm": "EC2.INTERNAL"
        },
        "ReleaseLabel": "ReleaseLabel",
        "VisibleToAllUsers": true
      }
    },
    "key": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Version": "2012-10-17T00:00:00Z",
          "Id": "key-default-1",
          "Statement": [
            {
              "Principal": {
                "AWS": [
                  "emrEc2Role",
                  "Arn"
                ]
              },
              "Action": "kms:*",
              "Resource": "*",
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow"
            },
            {
              "Action": "kms:*",
              "Resource": "*",
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "",
                  [
                    "arn:aws:iam::",
                    "AWS::AccountId",
                    ":root"
                  ]
                ]
              }
            }
          ]
        }
      }
    },
    "securityConfiguration": {
      "Type": "AWS::EMR::SecurityConfiguration",
      "Properties": {
        "SecurityConfiguration": {
          "AuthenticationConfiguration": {
            "KerberosConfiguration": {
              "Provider": "ClusterDedicatedKdc",
              "ClusterDedicatedKdcConfiguration": {
                "TicketLifetimeInHours": 24,
                "CrossRealmTrustConfiguration": {
                  "Realm": "AD.DOMAIN.COM",
                  "Domain": "ad.domain.com",
                  "AdminServer": "ad.domain.com",
                  "KdcServer": "ad.domain.com"
                }
              }
            }
          }
        }
      }
    },
    "emrRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "Path": "/",
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        ],
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "elasticmapreduce.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        }
      }
    }
  },
  "Outputs": {
    "keyArn": {
      "Value": [
        "key",
        "Arn"
      ]
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  CrossRealmTrustPrincipalPassword:
    Type: String
  KdcAdminPassword:
    Type: String
  Realm:
    Type: String
  InstanceType:
    Type: String
  ReleaseLabel:
    Type: String
  SubnetId:
    Type: String
Resources:
  cluster1:
    Type: 'AWS::EMR::Cluster'
    Properties:
      Instances:
        MasterInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnMaster
        CoreInstanceGroup:
          InstanceCount: 1
          InstanceType: !Ref InstanceType
          Market: ON_DEMAND
          Name: cfnCore
        Ec2SubnetId: !Ref SubnetId
      Name: CFNtest2
      JobFlowRole: !Ref emrEc2InstanceProfile
      KerberosAttributes:
        CrossRealmTrustPrincipalPassword: CfnIntegrationTest-1
        KdcAdminPassword: CfnIntegrationTest-1
        Realm: EC2.INTERNAL
      ServiceRole: !Ref emrRole
      ReleaseLabel: !Ref ReleaseLabel
      VisibleToAllUsers: true
      Tags:
        - Key: key1
          Value: value1
  key:
    Type: 'AWS::KMS::Key'
    Properties:
      KeyPolicy:
        Version: 2012-10-17
        Id: key-default-1
        Statement:
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !GetAtt
                - emrEc2Role
                - Arn
            Action: 'kms:*'
            Resource: '*'
          - Sid: Enable IAM User Permissions
            Effect: Allow
            Principal:
              AWS: !Join
                - ''
                - - 'arn:aws:iam::'
                  - !Ref 'AWS::AccountId'
                  - ':root'
            Action: 'kms:*'
            Resource: '*'
  emrRole1:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: elasticmapreduce.amazonaws.com
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole'
  emrEc2Role1:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2008-10-17
        Statement:
          - Sid: ''
            Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: 'sts:AssumeRole'
      Path: /
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role'
  emrEc2InstanceProfile1:
    Type: 'AWS::IAM::InstanceProfile'
    Properties:
      Path: /
      Roles:
        - !Ref emrEc2Role
Outputs:
  keyArn:
    Value: !GetAtt
      - key
      - Arn

```

```json
{
  "Outputs": {
    "keyArn": {
      "Value": [
        "key",
        "Arn"
      ]
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Parameters": {
    "Realm": {
      "Type": "String"
    },
    "InstanceType": {
      "Type": "String"
    },
    "ReleaseLabel": {
      "Type": "String"
    },
    "SubnetId": {
      "Type": "String"
    },
    "CrossRealmTrustPrincipalPassword": {
      "Type": "String"
    },
    "KdcAdminPassword": {
      "Type": "String"
    }
  },
  "Resources": {
    "emrEc2InstanceProfile": {
      "Type": "AWS::IAM::InstanceProfile",
      "Properties": {
        "Path": "/",
        "Roles": [
          "emrEc2Role"
        ]
      }
    },
    "cluster": {
      "Type": "AWS::EMR::Cluster",
      "Properties": {
        "ReleaseLabel": "ReleaseLabel",
        "SecurityConfiguration": "securityConfiguration1",
        "VisibleToAllUsers": true,
        "Tags": [
          {
            "Value": "value1",
            "Key": "key1"
          }
        ],
        "Instances": {
          "MasterInstanceGroup": {
            "Market": "ON_DEMAND",
            "Name": "cfnMaster",
            "InstanceCount": 1,
            "InstanceType": "InstanceType"
          },
          "CoreInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": "InstanceType",
            "Market": "ON_DEMAND",
            "Name": "cfnCore"
          },
          "Ec2SubnetId": "SubnetId"
        },
        "Name": "CFNtest2",
        "JobFlowRole": "emrEc2InstanceProfile",
        "KerberosAttributes": {
          "CrossRealmTrustPrincipalPassword": "CfnIntegrationTest-1",
          "KdcAdminPassword": "CfnIntegrationTest-1",
          "Realm": "EC2.INTERNAL"
        },
        "ServiceRole": "emrRole"
      }
    },
    "key": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Version": "2012-10-17T00:00:00Z",
          "Id": "key-default-1",
          "Statement": [
            {
              "Resource": "*",
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "emrEc2Role",
                  "Arn"
                ]
              },
              "Action": "kms:*"
            },
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "",
                  [
                    "arn:aws:iam::",
                    "AWS::AccountId",
                    ":root"
                  ]
                ]
              },
              "Action": "kms:*",
              "Resource": "*",
              "Sid": "Enable IAM User Permissions"
            }
          ]
        }
      }
    },
    "securityConfiguration": {
      "Type": "AWS::EMR::SecurityConfiguration",
      "Properties": {
        "SecurityConfiguration": {
          "AuthenticationConfiguration": {
            "KerberosConfiguration": {
              "ClusterDedicatedKdcConfiguration": {
                "TicketLifetimeInHours": 24,
                "CrossRealmTrustConfiguration": {
                  "Realm": "AD.DOMAIN.COM",
                  "Domain": "ad.domain.com",
                  "AdminServer": "ad.domain.com",
                  "KdcServer": "ad.domain.com"
                }
              },
              "Provider": "ClusterDedicatedKdc"
            }
          }
        }
      }
    },
    "emrRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "elasticmapreduce.amazonaws.com"
              },
              "Action": "sts:AssumeRole",
              "Sid": ""
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        ]
      }
    },
    "emrEc2Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "ec2.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
        ]
      }
    }
  }
}

```

```json
{
  "Resources": {
    "cluster1": {
      "Type": "AWS::EMR::Cluster",
      "Properties": {
        "Tags": [
          {
            "Key": "key1",
            "Value": "value1"
          }
        ],
        "Instances": {
          "MasterInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": "InstanceType",
            "Market": "ON_DEMAND",
            "Name": "cfnMaster"
          },
          "CoreInstanceGroup": {
            "InstanceCount": 1,
            "InstanceType": "InstanceType",
            "Market": "ON_DEMAND",
            "Name": "cfnCore"
          },
          "Ec2SubnetId": "SubnetId"
        },
        "Name": "CFNtest2",
        "JobFlowRole": "emrEc2InstanceProfile",
        "KerberosAttributes": {
          "CrossRealmTrustPrincipalPassword": "CfnIntegrationTest-1",
          "KdcAdminPassword": "CfnIntegrationTest-1",
          "Realm": "EC2.INTERNAL"
        },
        "ServiceRole": "emrRole",
        "ReleaseLabel": "ReleaseLabel",
        "VisibleToAllUsers": true
      }
    },
    "key": {
      "Properties": {
        "KeyPolicy": {
          "Statement": [
            {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "emrEc2Role",
                  "Arn"
                ]
              },
              "Action": "kms:*",
              "Resource": "*"
            },
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": [
                  "",
                  [
                    "arn:aws:iam::",
                    "AWS::AccountId",
                    ":root"
                  ]
                ]
              },
              "Action": "kms:*",
              "Resource": "*",
              "Sid": "Enable IAM User Permissions"
            }
          ],
          "Version": "2012-10-17T00:00:00Z",
          "Id": "key-default-1"
        }
      },
      "Type": "AWS::KMS::Key"
    },
    "emrRole1": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        ],
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                "Service": "elasticmapreduce.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Path": "/"
      }
    },
    "emrEc2Role1": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2008-10-17T00:00:00Z",
          "Statement": [
            {
              "Principal": {
                "Service": "ec2.amazonaws.com"
              },
              "Action": "sts:AssumeRole",
              "Sid": "",
              "Effect": "Allow"
            }
          ]
        },
        "Path": "/",
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
        ]
      }
    },
    "emrEc2InstanceProfile1": {
      "Type": "AWS::IAM::InstanceProfile",
      "Properties": {
        "Path": "/",
        "Roles": [
          "emrEc2Role"
        ]
      }
    }
  },
  "Outputs": {
    "keyArn": {
      "Value": [
        "key",
        "Arn"
      ]
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Parameters": {
    "SubnetId": {
      "Type": "String"
    },
    "CrossRealmTrustPrincipalPassword": {
      "Type": "String"
    },
    "KdcAdminPassword": {
      "Type": "String"
    },
    "Realm": {
      "Type": "String"
    },
    "InstanceType": {
      "Type": "String"
    },
    "ReleaseLabel": {
      "Type": "String"
    }
  }
}

```