---
title: "ELB without secure protocol"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_without_secure_protocol"
  id: "80908a75-586b-4c61-ab04-490f4f4525b8"
  display_name: "ELB without secure protocol"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `80908a75-586b-4c61-ab04-490f4f4525b8`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html)

### Description

 Listeners on Classic Elastic Load Balancers must use encrypted protocols to protect data in transit. Listeners configured with plaintext protocols (for example, `HTTP` or `TCP`) can expose sensitive information and allow interception or tampering.
 
 For `AWS::ElasticLoadBalancing::LoadBalancer` resources, this rule checks each entry in `Properties.Listeners` and requires the `Protocol` and `InstanceProtocol` fields (when present) to be set to `SSL` or `HTTPS`. Resources missing these properties or with `Protocol`/`InstanceProtocol` set to values like `HTTP` or `TCP` will be flagged as insecure. 
 
 Secure listener example (CloudFormation YAML):

```yaml
MyLoadBalancer:
  Type: AWS::ElasticLoadBalancing::LoadBalancer
  Properties:
    Listeners:
      - Protocol: HTTPS
        LoadBalancerPort: 443
        InstanceProtocol: HTTPS
        InstancePort: 8443
        SSLCertificateId: arn:aws:iam::123456789012:server-certificate/my-cert
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Resources:
    MyLoadBalancer1:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
          AvailabilityZones:
          - "us-east-2a"
          CrossZone: true
          Listeners:
          - InstancePort: '80'
            InstanceProtocol: HTTPS
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
    "MyLoadBalancer2": {
      "Properties": {
        "AvailabilityZones": [
          "us-east-2a"
        ],
        "CrossZone": true,
        "Listeners": [
          {
            "InstancePort": "9443",
            "InstanceProtocol": "SSL",
            "LoadBalancerPort": "443",
            "PolicyNames": [
              "My-SSLNegotiation-Policy"
            ],
            "Protocol": "SSL",
            "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-certificate"
          }
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
        ]
      },
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer"
    }
  }
}

```

```yaml
#this code is a correct code for which the query should not find any result
Resources:
    MyLoadBalancer2:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
          AvailabilityZones:
          - "us-east-2a"
          CrossZone: true
          Listeners:
          - InstancePort: '9443'
            InstanceProtocol: SSL
            LoadBalancerPort: '443'
            Protocol: SSL
            PolicyNames:
            - My-SSLNegotiation-Policy
            SSLCertificateId: arn:aws:iam::123456789012:server-certificate/my-server-certificate
          Policies:
          - PolicyName: My-SSLNegotiation-Policy
            PolicyType: SSLNegotiationPolicyType
            Attributes:
            - Name: Reference-Security-Policy
              Value: ELBSecurityPolicy-TLS-1-2-2017-01

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "Listeners": [
          {
            "InstancePort": "80",
            "InstanceProtocol": "HTTP",
            "LoadBalancerPort": "443",
            "Protocol": "HTTP",
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
                "Name": "Reference-Security-Policy",
                "Value": "ELBSecurityPolicy-TLS-1-2-2017-01"
              }
            ]
          }
        ],
        "AvailabilityZones": [
          "us-east-2a"
        ],
        "CrossZone": true
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
          - LoadBalancerPort: '443'
            InstancePort: '80'
            InstanceProtocol: HTTP
            Protocol: HTTP
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