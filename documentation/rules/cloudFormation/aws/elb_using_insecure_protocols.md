---
title: "ELB using insecure protocols"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_using_insecure_protocols"
  id: "61a94903-3cd3-4780-88ec-fc918819b9c8"
  display_name: "ELB using insecure protocols"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `61a94903-3cd3-4780-88ec-fc918819b9c8`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html)

### Description

Load balancer policies that permit SSLv2, SSLv3, TLSv1.0, or TLSv1.1 expose TLS connections to known cryptographic weaknesses and downgrade attacks, increasing the risk of intercepted or tampered data in transit.
 
 In CloudFormation, this rule checks `AWS::ElasticLoadBalancing::LoadBalancer` resources and flags any `Policies[].Attributes[].Name` equal to `Protocol-SSLv2`, `Protocol-SSLv3`, `Protocol-TLSv1`, or `Protocol-TLSv1.1`. Replace these identifiers with TLS 1.2+ protocol settings or attach a current ELB security policy that enforces strong TLS versions and ciphers. Resources with the listed attribute values will be reported.

Secure configuration example (use TLS 1.2 or newer):

```yaml
MyLoadBalancer:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    Policies:
      - PolicyName: TLS12Policy
        PolicyType: SSLNegotiationPolicyType
        Attributes:
          - Name: Protocol-TLSv1.2
            Value: "true"
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
    MyLoadBalancer:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
          AvailabilityZones:
          - "us-east-2a"
          CrossZone: true
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
          Policies:
          - PolicyName: My-SSLNegotiation-Policy
            PolicyType: SSLNegotiationPolicyType
            Attributes:
            - Name: Reference-Security-Policy
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
```

```json
{
  "Resources": {
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "HealthCheck": {
          "Interval": "10",
          "Timeout": "5",
          "Target": "HTTP:80/",
          "HealthyThreshold": "2",
          "UnhealthyThreshold": "3"
        },
        "Policies": [
          {
            "PolicyName": "My-SSLNegotiation-Policy",
            "PolicyType": "SSLNegotiationPolicyType",
            "Attributes": [
              {
                "Name": "Reference-Security-Policy",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              }
            ]
          }
        ],
        "AvailabilityZones": [
          "us-east-2a"
        ],
        "CrossZone": true,
        "Listeners": [
          {
            "PolicyNames": [
              "My-SSLNegotiation-Policy"
            ],
            "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-certificate",
            "InstancePort": "80",
            "InstanceProtocol": "HTTP",
            "LoadBalancerPort": "443",
            "Protocol": "HTTPS"
          }
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "AvailabilityZones": [
          "us-east-2a"
        ],
        "CrossZone": true,
        "Listeners": [
          {
            "InstanceProtocol": "HTTP",
            "LoadBalancerPort": "443",
            "Protocol": "HTTPS",
            "PolicyNames": [
              "My-SSLNegotiation-Policy"
            ],
            "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-certificate",
            "InstancePort": "80"
          }
        ],
        "HealthCheck": {
          "HealthyThreshold": "2",
          "UnhealthyThreshold": "3",
          "Interval": "10",
          "Timeout": "5",
          "Target": "HTTP:80/"
        },
        "Policies": [
          {
            "PolicyName": "My-SSLNegotiation-Policy",
            "PolicyType": "SSLNegotiationPolicyType",
            "Attributes": [
              {
                "Name": "Protocol-SSLv2",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              },
              {
                "Name": "Reference-Security-Policy",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              }
            ]
          },
          {
            "PolicyName": "My-SSLNegotiation-Policy2",
            "PolicyType": "SSLNegotiationPolicyType",
            "Attributes": [
              {
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01",
                "Name": "Protocol-TLSv1"
              }
            ]
          }
        ]
      }
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
Resources:
    MyLoadBalancer:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
          AvailabilityZones:
          - "us-east-2a"
          CrossZone: true
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
          Policies:
          - PolicyName: My-SSLNegotiation-Policy
            PolicyType: SSLNegotiationPolicyType
            Attributes:
            - Name: Protocol-SSLv2
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
            - Name: Reference-Security-Policy
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
          - PolicyName: My-SSLNegotiation-Policy2
            PolicyType: SSLNegotiationPolicyType
            Attributes:
            - Name: Protocol-TLSv1
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
```