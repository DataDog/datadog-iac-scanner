---
title: "ALB listening on HTTP"
group_id: "Ansible / AWS"
meta:
  name: "aws/alb_listening_on_http"
  id: "f81d63d2-c5d7-43a4-a5b5-66717a41c895"
  display_name: "ALB listening on HTTP"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `f81d63d2-c5d7-43a4-a5b5-66717a41c895`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/elb_application_lb_module.html)

### Description

Application Load Balancers (ALB) must terminate TLS and use HTTPS listeners to protect traffic in transit and prevent interception or downgrade attacks. Serving application traffic over plain HTTP exposes credentials and sensitive data to eavesdropping.

For Ansible ALB resources (modules `community.aws.elb_application_lb` and `elb_application_lb`), ensure the `listeners[].Protocol` property is set to `"HTTPS"`. Resources missing the `Protocol` property or with `Protocol` set to any value other than `"HTTPS"` are flagged. When using HTTPS, also configure a valid TLS certificate (for example via `Certificates: - CertificateArn: ...`) or implement an HTTP listener only to perform redirects to HTTPS rather than serving plaintext.

Secure configuration example:

```yaml
- name: Create ALB with HTTPS listener
  community.aws.elb_application_lb:
    name: my-alb
    state: present
    listeners:
      - Protocol: HTTPS
        Port: 443
        Certificates:
          - CertificateArn: arn:aws:acm:us-east-1:123456789012:certificate/abcdef01-2345-6789-abcd-ef0123456789
        DefaultActions:
          - Type: forward
            TargetGroupArn: arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/abcdef0123456789
```

## Compliant Code Examples
```yaml
- name: my_elb_application
  community.aws.elb_application_lb:
    name: myelb
    security_groups:
    - sg-12345678
    - my-sec-group
    subnets:
    - subnet-012345678
    - subnet-abcdef000
    listeners:
    - Protocol: HTTPS
      Port: 80
      SslPolicy: ELBSecurityPolicy-2015-05
      Certificates:
      - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
      DefaultActions:
      - Type: forward
        TargetGroupName: targetname
    state: present
    # trigger validation

```
## Non-Compliant Code Examples
```yaml
- name: my_elb_application
  community.aws.elb_application_lb:
    name: myelb
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    listeners:
      - Protocol: HTTP
        Port: 80
        SslPolicy: ELBSecurityPolicy-2015-05
        Certificates:
          - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
        DefaultActions:
          - Type: forward
            TargetGroupName: targetname
    state: present
- name: my_elb_application2
  community.aws.elb_application_lb:
    name: myelb2
    security_groups:
      - sg-12345678
      - my-sec-group
    subnets:
      - subnet-012345678
      - subnet-abcdef000
    listeners:
      Port: 80
      SslPolicy: ELBSecurityPolicy-2015-05
      Certificates:
        - CertificateArn: arn:aws:iam::12345678987:server-certificate/test.domain.com
      DefaultActions:
        - Type: forward
          TargetGroupName: targetname
    state: present

```