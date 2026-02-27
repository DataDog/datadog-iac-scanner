---
title: "ELB sensitive port is exposed to entire network"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_sensitive_port_is_exposed_to_entire_network"
  id: "78055456-f670-4d2e-94d5-392d1cf4f5e4"
  display_name: "ELB sensitive port is exposed to entire network"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `78055456-f670-4d2e-94d5-392d1cf4f5e4`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html)

### Description

Load balancer security groups that allow ingress from the entire internet (for example, `0.0.0.0/0` or `::/0`) to sensitive ports expose management, database, and application endpoints to unauthorized access and exploitation.
 
 Check load balancer resources (`AWS::ElasticLoadBalancing::LoadBalancer` and `AWS::ElasticLoadBalancingV2::LoadBalancer`) and their referenced security groups. Examine `SecurityGroupIngress` entries (`Properties.SecurityGroupIngress`) for `IpProtocol`, `FromPort`/`ToPort`, and `CidrIp`. The `CidrIp` value must not be a `/0` range for ports that map to sensitive services (for example, SSH `22`, RDP `3389`, and database ports).
 
 If a load balancer lists `SecurityGroups`, validate those `AWS::EC2::SecurityGroup` resources. If the load balancer is associated via Amazon EC2 instances, validate those instances' `Properties.SecurityGroups` as well. Ingress rules that include a `/0` CIDR covering the flagged ports will be reported.

Secure example restricting SSH to a single admin IP:

```yaml
AdminSG:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Restrict SSH to admin workstation
    VpcId: vpc-01234567
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 203.0.113.5/32
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyLoadBalancer:
      Type: AWS::ElasticLoadBalancing::LoadBalancer
      Properties:
        AvailabilityZones:
        - "us-east-2a"
        CrossZone: true
        Scheme: internet-facing
        Listeners:
        - InstancePort: '80'
          InstanceProtocol: HTTP
          LoadBalancerPort: '443'
          Protocol: HTTPS
          PolicyNames:
          - My-SSLNegotiation-Policy
          SSLCertificateId: arn:aws:iam::123456789012:server-certificate/my-server-certificate
        HealthCheck:
          Target: HTTP:80/
          HealthyThreshold: '2'
          UnhealthyThreshold: '3'
          Interval: '10'
          Timeout: '5'
        SecurityGroups:
          [ !Ref LBNegativeSecGroup01 ]
        Policies:
        - PolicyName: My-SSLNegotiation-Policy
          PolicyType: SSLNegotiationPolicyType
          Attributes:
          - Name: Reference-Security-Policy
            Value: ELBSecurityPolicy-TLS-1-2-2017-01
  LBNegativeSecGroup01:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow http and ssh
        VpcId: my-vpc
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 127.0.0.1/32
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 127.0.0.1/32
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Parameters": {
    "MySubnet": {
      "Type": "List\u003cString\u003e",
      "Description": "My subnet"
    }
  },
  "Resources": {
    "InstancesNegativeSecGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http and ssh",
        "VpcId": "my-vpc",
        "SecurityGroupIngress": [
          {
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22
          },
          {
            "IpProtocol": "tcp",
            "FromPort": 77,
            "ToPort": 77,
            "CidrIp": "127.0.0.1/0"
          }
        ],
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22
          }
        ]
      }
    },
    "EC2Instance01": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": "t3.2xlarge",
        "SecurityGroups": [
          "InstancesNegativeSecGroup"
        ],
        "KeyName": "my-rsa-key",
        "ImageId": "ami-79fd7eee"
      }
    },
    "EC2Instance02": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": "t3.2xlarge",
        "SecurityGroups": [
          "InstancesNegativeSecGroup"
        ],
        "KeyName": "my-rsa-key",
        "ImageId": "ami-79fd7eee"
      }
    },
    "NetworkLoadBalancerTargetGroup": {
      "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
      "Properties": {
        "Name": "t10-networklb-target",
        "Port": 443,
        "Protocol": "TCP",
        "VpcId": "t10-vpc-id",
        "TargetGroupAttributes": [
          {
            "Value": 60,
            "Key": "deregistration_delay.timeout_seconds"
          }
        ],
        "Targets": [
          {
            "Id": "EC2Instance01",
            "Port": 443
          },
          {
            "Id": "EC2Instance02",
            "Port": 443
          }
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "t10-networklb-target"
          }
        ]
      }
    },
    "NetworkLoadBalancerListener": {
      "Type": "AWS::ElasticLoadBalancingV2::Listener",
      "Properties": {
        "DefaultActions": [
          {
            "Type": "forward",
            "TargetGroupArn": "NetworkLoadBalancerTargetGroup"
          }
        ],
        "LoadBalancerArn": "NetworkLoadBalancer",
        "Port": 443,
        "Protocol": "TCP"
      }
    },
    "NetworkLoadBalancerListenerCert": {
      "Type": "AWS::ElasticLoadBalancingV2::ListenerCertificate",
      "Properties": {
        "Certificates": [
          {
            "CertificateArn": "arn:aws:acm:eu-west-1:xxxaccountxxx:certificate/123456...."
          }
        ],
        "ListenerArn": "NetworkLoadBalancerListener"
      }
    },
    "NetworkLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "Properties": {
        "Name": "t10-networkloadbalancer",
        "Scheme": "internet-facing",
        "Subnets": "MySubnet",
        "Type": "network",
        "Tags": [
          {
            "Key": "Name",
            "Value": "t10-networklb"
          }
        ]
      }
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Parameters": {
    "MySubnets": {
      "Description": "My subnet",
      "Type": "List\u003cString\u003e"
    }
  },
  "Resources": {
    "IPTargetGroup": {
      "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
      "Properties": {
        "VpcId": "my-vpc",
        "Protocol": "HTTP",
        "HealthCheckIntervalSeconds": 10,
        "UnhealthyThresholdCount": 2,
        "Port": 80,
        "TargetType": "ip",
        "Matcher": {
          "HttpCode": "200"
        },
        "HealthCheckPath": "/health/check",
        "HealthCheckProtocol": "HTTP",
        "HealthCheckTimeoutSeconds": 5,
        "HealthyThresholdCount": 2
      }
    },
    "TestListenerRule1": {
      "Properties": {
        "Priority": 1,
        "ListenerArn": "HTTPALBListener",
        "Conditions": [
          {
            "Field": "host-header",
            "Values": [
              "test1.checkmarx.com"
            ]
          }
        ],
        "Actions": [
          {
            "TargetGroupArn": "IPTargetGroup",
            "Order": 1,
            "ForwardConfig": {
              "TargetGroups": [
                {
                  "TargetGroupArn": "IPTargetGroup",
                  "Weight": 1
                }
              ],
              "TargetGroupStickinessConfig": {
                "Enabled": false
              }
            },
            "Type": "forward"
          }
        ]
      },
      "Type": "AWS::ElasticLoadBalancingV2::ListenerRule"
    },
    "ApplicationLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "Properties": {
        "Name": "ip-target-alb",
        "Subnets": "MySubnets",
        "SecurityGroups": [
          "ALBNegativeSecGroup"
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "ip-target-alb"
          }
        ]
      }
    },
    "ALBNegativeSecGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http and ssh",
        "VpcId": "my-vpc",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "127.0.0.1/32"
          },
          {
            "IpProtocol": "tcp",
            "FromPort": 77,
            "ToPort": 77,
            "CidrIp": "127.0.0.1/0"
          }
        ],
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22
          }
        ]
      }
    },
    "HTTPALBListener": {
      "Type": "AWS::ElasticLoadBalancingV2::Listener",
      "Properties": {
        "LoadBalancerArn": "ApplicationLoadBalancer",
        "Port": 80,
        "Protocol": "HTTP",
        "DefaultActions": [
          {
            "Type": "forward",
            "TargetGroupArn": "IPTargetGroup"
          }
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  MySubnets:
    Description: "My subnet"
    Type: List<String>
Resources:
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: ip-target-alb
      Subnets: !Ref MySubnets
      SecurityGroups:
        - !Ref ALBSecGroup
      Tags:
        - Key: Name
          Value: ip-target-alb
  ALBSecGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow http and ssh
        VpcId: my-vpc
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 127.0.0.1/32
        - IpProtocol: tcp
          FromPort: 6379
          ToPort: 6379
          CidrIp: 127.0.0.1/0
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  HTTPALBListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref ApplicationLoadBalancer
      Port: 80
      Protocol: HTTP
      DefaultActions:
          - Type: forward
            TargetGroupArn: !Ref IPTargetGroup
  IPTargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
        VpcId: my-vpc
        Port: 80
        Protocol: HTTP
        TargetType: ip
        Matcher:
            HttpCode: '200'
        HealthCheckIntervalSeconds: 10
        HealthCheckPath: /health/check
        HealthCheckProtocol: HTTP
        HealthCheckTimeoutSeconds: 5
        HealthyThresholdCount: 2
        UnhealthyThresholdCount: 2
  TestListenerRule1:
    Type: "AWS::ElasticLoadBalancingV2::ListenerRule"
    Properties:
        Priority: 1
        ListenerArn: !Ref HTTPALBListener
        Conditions:
          - Field: "host-header"
            Values:
              - "test1.checkmarx.com"
        Actions:
          - Type: "forward"
            TargetGroupArn: !Ref IPTargetGroup
            Order: 1
            ForwardConfig:
                TargetGroups:
                  - TargetGroupArn: !Ref IPTargetGroup
                    Weight: 1
                TargetGroupStickinessConfig:
                    Enabled: false

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  MySubnet:
    Description: "My subnet"
    Type: List<String>
Resources:
  GatewayLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: my-gateway-load-balancer
      Scheme: internet-facing
      Type: gateway
      Subnets: !Ref MySubnet
  InstancesSecGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow http and ssh
        VpcId: my-vpc
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 127.0.0.1/32
        - IpProtocol: tcp
          FromPort: 636
          ToPort: 636
          CidrIp: 127.0.0.1/0
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  EC2Instance01:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t3.2xlarge
      SecurityGroups:
      - !Ref 'InstancesSecGroup'
      KeyName: my-rsa-key
      ImageId: ami-79fd7eee
  EC2Instance02:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t3.2xlarge
      SecurityGroups:
      - !Ref 'InstancesSecGroup'
      KeyName: my-rsa-key
      ImageId: ami-79fd7eee
  GatewayLoadBalancerTargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Name: t10-networklb-target
      Port: 443
      Protocol: TCP
      VpcId: t10-vpc-id
      TargetGroupAttributes:
        - Key: deregistration_delay.timeout_seconds
          Value: '60'
      Targets:
      - Id: !Ref EC2Instance01
        Port: 443
      - Id: !Ref EC2Instance02
        Port: 443
      Tags:
        - Key: Name
          Value: t10-networklb-target
  GatewayLoadBalancerListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      DefaultActions:
      - Type: forward
        TargetGroupArn: !Ref GatewayLoadBalancerTargetGroup
      LoadBalancerArn: !Ref GatewayLoadBalancer
      Port: 443
      Protocol: TCP
  GatewayLoadBalancerListenerCert:
    Type: AWS::ElasticLoadBalancingV2::ListenerCertificate
    Properties:
      Certificates:
        - CertificateArn: arn:aws:acm:eu-west-1:xxxaccountxxx:certificate/123456....
      ListenerArn: !Ref GatewayLoadBalancerListener

```

```json
{
  "Resources": {
    "MyLoadBalancer": {
      "Properties": {
        "Scheme": "internet-facing",
        "Listeners": [
          {
            "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-certificate",
            "InstancePort": "80",
            "InstanceProtocol": "HTTP",
            "LoadBalancerPort": "443",
            "Protocol": "HTTPS",
            "PolicyNames": [
              "My-SSLNegotiation-Policy"
            ]
          }
        ],
        "HealthCheck": {
          "HealthyThreshold": "2",
          "UnhealthyThreshold": "3",
          "Interval": "10",
          "Timeout": "5",
          "Target": "HTTP:80/"
        },
        "SecurityGroups": [
          "LBSecGroup"
        ],
        "Policies": [
          {
            "Attributes": [
              {
                "Name": "Reference-Security-Policy",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              }
            ],
            "PolicyName": "My-SSLNegotiation-Policy",
            "PolicyType": "SSLNegotiationPolicyType"
          }
        ],
        "AvailabilityZones": [
          "us-east-2a"
        ],
        "CrossZone": true
      },
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer"
    },
    "LBSecGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http and ssh",
        "VpcId": "my-vpc",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 50,
            "ToPort": 80,
            "CidrIp": "127.0.0.1/0"
          },
          {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "127.0.0.1/0"
          }
        ],
        "SecurityGroupEgress": [
          {
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp"
          }
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z"
}

```