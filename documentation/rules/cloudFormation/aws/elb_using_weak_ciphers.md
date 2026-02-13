---
title: "ELB using weak ciphers"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_using_weak_ciphers"
  id: "809f77f8-d10e-4842-a84f-3be7b6ff1190"
  display_name: "ELB using weak ciphers"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `809f77f8-d10e-4842-a84f-3be7b6ff1190`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html)

### Description

ELB security policies must not include weak TLS cipher suites because weak ciphers can be exploited to downgrade or break the confidentiality and integrity of TLS connections to the load balancer.
 
 Check `AWS::ElasticLoadBalancing::LoadBalancer` resources and verify the `Policies[].Attributes[].Name` values (the cipher identifiers or referenced policy names) do not match any known weak ciphers in the IANA, OpenSSL, or GnuTLS lists. Resources with `Attributes` that match a weak-cipher identifier will be flagged. Instead, use AWS predefined strong ELB security policy names or an `SSLNegotiationPolicyType` policy that explicitly references modern cipher suites (TLS 1.2+ with ECDHE and AES-GCM). 
 
 Secure configuration example using a modern predefined policy:

```yaml
MyLoadBalancer:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    Listeners:
      - LoadBalancerPort: 443
        InstancePort: 443
        Protocol: HTTPS
        InstanceProtocol: HTTPS
        SSLCertificateId: arn:aws:iam::123456789012:server-certificate/my-cert
    Policies:
      - PolicyName: SecureSSLPolicy
        PolicyType: SSLNegotiationPolicyType
        Attributes:
          - Name: Reference-Security-Policy
            Value: ELBSecurityPolicy-TLS-1-2-2017-01
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
        "AvailabilityZones": [
          "us-east-2a"
        ],
        "CrossZone": true,
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
        "Policies": [
          {
            "PolicyType": "SSLNegotiationPolicyType",
            "Attributes": [
              {
                "Name": "Reference-Security-Policy",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              }
            ],
            "PolicyName": "My-SSLNegotiation-Policy"
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
            "InstancePort": "80",
            "InstanceProtocol": "HTTP",
            "LoadBalancerPort": "443",
            "Protocol": "HTTPS",
            "PolicyNames": [
              "My-SSLNegotiation-Policy"
            ],
            "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-certificate"
          }
        ],
        "HealthCheck": {
          "Target": "HTTP:80/",
          "HealthyThreshold": "2",
          "UnhealthyThreshold": "3",
          "Interval": "10",
          "Timeout": "5"
        },
        "Policies": [
          {
            "PolicyName": "My-SSLNegotiation-Policy",
            "PolicyType": "SSLNegotiationPolicyType",
            "Attributes": [
              {
                "Name": "TLS_RSA_NULL_SHA1",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              },
              {
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01",
                "Name": "DHE-DSS-DES-CBC3-SHA"
              }
            ]
          },
          {
            "PolicyName": "My-SSLNegotiation-Policy2",
            "PolicyType": "SSLNegotiationPolicyType",
            "Attributes": [
              {
                "Name": "TLS_DHE_PSK_WITH_NULL_SHA256",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
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
            - Name: TLS_RSA_NULL_SHA1
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
            - Name: DHE-DSS-DES-CBC3-SHA
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
          - PolicyName: My-SSLNegotiation-Policy2
            PolicyType: SSLNegotiationPolicyType
            Attributes:
            - Name: TLS_DHE_PSK_WITH_NULL_SHA256
              Value: ELBSecurityPolicy-TLS-1-2-2017-01
```