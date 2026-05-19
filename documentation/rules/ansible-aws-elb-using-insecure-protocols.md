---
title: "ELB using insecure protocols"
group_id: "Ansible / AWS"
meta:
  name: ""aws/elb_using_insecure_protocols""
  id: "ansible-aws-elb-using-insecure-protocols"
  display_name: "ELB using insecure protocols"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-elb-using-insecure-protocols{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/elb_application_lb_module.html)

### Description

Load balancer listeners must use secure TLS policies to prevent protocol downgrade and known cryptographic vulnerabilities that could allow interception or decryption of client traffic.

For Ansible ELB modules (`community.aws.elb_network_lb`, `elb_network_lb`, `amazon.aws.elb_application_lb`, `elb_application_lb`), the `listeners` property must be defined and each listener must include `SslPolicy` set to a modern, secure policy (not legacy SSL/TLS protocol policies).

This rule flags resources missing `listeners`, listeners missing `SslPolicy`, or any `SslPolicy` set to `Protocol-SSLv2`, `Protocol-SSLv3`, `Protocol-TLSv1`, or `Protocol-TLSv1.1`. 

Secure example (use a TLS 1.2+ policy):

```yaml
- name: create application load balancer
  amazon.aws.elb_application_lb:
    name: my-alb
    listeners:
      - Protocol: HTTPS
        Port: 443
        SslPolicy: ELBSecurityPolicy-TLS-1-2-2017-01
        CertificateArn: arn:aws:acm:us-east-1:123456789012:certificate/abcd-1234
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: elb1
  amazon.aws.elb_application_lb:
    name: myelb1
    security_groups:
    - sg-12345678
    - my-sec-group
    subnets:
    - subnet-012345678
    - subnet-abcdef000
    listeners:
    - Protocol: HTTP   # Required. The protocol for connections from clients to the load balancer (HTTP or HTTPS) (case-sensitive).
      Port: 80   # Required. The port on which the load balancer is listening.
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
      SslPolicy: ELBSecurityPolicy-2015-05
      Certificates:   # The ARN of the certificate (only one certficate ARN should be provided)
      - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
      DefaultActions:
      - Type: forward     # Required.
        TargetGroupName:     # Required. The name of the target group
    state: present
- name: elb2
  community.aws.elb_network_lb:
    name: myelb2
    security_groups:
    - sg-12345678
    - my-sec-group
    subnets:
    - subnet-012345678
    - subnet-abcdef000
    listeners:
    - Protocol: HTTP   # Required. The protocol for connections from clients to the load balancer (HTTP or HTTPS) (case-sensitive).
      Port: 80   # Required. The port on which the load balancer is listening.
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
      SslPolicy: ELBSecurityPolicy-2015-05
      Certificates:   # The ARN of the certificate (only one certficate ARN should be provided)
      - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
      DefaultActions:
      - Type: forward     # Required.
        TargetGroupName:     # Required. The name of the target group
    state: present

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: elb1
  amazon.aws.elb_application_lb:
    name: myelb1
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    state: present
- name: elb2
  amazon.aws.elb_application_lb:
    name: myelb2
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    listeners:
      - Protocol: HTTP # Required. The protocol for connections from clients to the load balancer (HTTP or HTTPS) (case-sensitive).
        Port: 80 # Required. The port on which the load balancer is listening.
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
        Certificates: # The ARN of the certificate (only one certficate ARN should be provided)
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward # Required.
            TargetGroupName: # Required. The name of the target group
    state: present
- name: elb3
  amazon.aws.elb_application_lb:
    name: myelb3
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    listeners:
      - Protocol: HTTP # Required. The protocol for connections from clients to the load balancer (HTTP or HTTPS) (case-sensitive).
        Port: 80 # Required. The port on which the load balancer is listening.
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
        SslPolicy: Protocol-SSLv2
        Certificates: # The ARN of the certificate (only one certficate ARN should be provided)
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward # Required.
            TargetGroupName: # Required. The name of the target group
    state: present
- name: elb4
  community.aws.elb_network_lb:
    name: myelb4
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    state: present
- name: elb5
  community.aws.elb_network_lb:
    name: myelb5
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    listeners:
      - Protocol: HTTP # Required. The protocol for connections from clients to the load balancer (HTTP or HTTPS) (case-sensitive).
        Port: 80 # Required. The port on which the load balancer is listening.
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
        Certificates: # The ARN of the certificate (only one certficate ARN should be provided)
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward # Required.
            TargetGroupName: # Required. The name of the target group
    state: present
- name: elb6
  community.aws.elb_network_lb:
    name: myelb6
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    listeners:
      - Protocol: HTTP # Required. The protocol for connections from clients to the load balancer (HTTP or HTTPS) (case-sensitive).
        Port: 80 # Required. The port on which the load balancer is listening.
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
        SslPolicy: Protocol-TLSv1.1
        Certificates: # The ARN of the certificate (only one certficate ARN should be provided)
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward # Required.
            TargetGroupName: # Required. The name of the target group
    state: present

```