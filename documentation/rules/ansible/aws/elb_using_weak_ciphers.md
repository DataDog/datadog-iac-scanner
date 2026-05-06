---
title: "ELB using weak ciphers"
group_id: "Ansible / AWS"
meta:
  name: "aws/elb_using_weak_ciphers"
  id: "2034fb37-bc23-4ca0-8d95-2b9f15829ab5"
  display_name: "ELB using weak ciphers"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}2034fb37-bc23-4ca0-8d95-2b9f15829ab5{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/elb_application_lb_module.html)

### Description

ELB listeners must specify a strong SSL/TLS policy because weak cipher suites can enable protocol downgrade, interception, or decryption of traffic between clients and the load balancer. For Ansible ELB Application and Network load balancer modules (`amazon.aws.elb_application_lb`, `elb_application_lb`, `community.aws.elb_network_lb`, `elb_network_lb`), the `listeners` list must be defined and each listener must include the `SslPolicy` property set to a non-weak policy.

Resources missing `listeners` or listener entries missing `SslPolicy` are flagged. Any `SslPolicy` that matches a known weak policy in your baseline should be replaced with an AWS-managed strong policy (for example, a TLS 1.2+ policy) or a custom policy that excludes weak ciphers.

Secure configuration example:

```yaml
- name: Create ALB with strong TLS policy
  amazon.aws.elb_application_lb:
    name: my-alb
    listeners:
      - Protocol: HTTPS
        Port: 443
        SslPolicy: ELBSecurityPolicy-TLS-1-2-2017-01
        CertificateArn: arn:aws:acm:us-west-2:123456789012:certificate/abcd-1234
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
        SslPolicy: DHE-DSS-DES-CBC3-SHA
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
      - Protocol: HTTP
        Port: 80
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
        Certificates:
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward
            TargetGroupName: target
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
      - Protocol: HTTP
        Port: 80
        # The security policy that defines which ciphers and protocols are supported. The default is the current predefined security policy.
        SslPolicy: TLS_RSA_NULL_MD5
        Certificates:
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward
            TargetGroupName: target
    state: present

```