---
title: "ELB using weak ciphers"
group_id: "Terraform / AWS"
meta:
  name: "aws/elb_using_weak_ciphers"
  id: "4a800e14-c94a-442d-9067-5a2e9f6c0a4c"
  display_name: "ELB using weak ciphers"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `4a800e14-c94a-442d-9067-5a2e9f6c0a4c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/load_balancer_policy)

### Description

 Elastic Load Balancers (ELBs) with weak cipher configurations present a significant security vulnerability as they can be exploited through various attacks like BEAST, POODLE, or FREAK, potentially leading to data breaches and session hijacking. Weak ciphers such as DES-CBC3-SHA or TLS_RSA_ARCFOUR_128_SHA1 are considered cryptographically insufficient by modern standards and may be exploited by attackers to decrypt sensitive data passing through the load balancer. To mitigate this risk, configure your ELB with strong cipher suites, as shown below:

```hcl
policy_attribute {
  name  = "ECDHE-ECDSA-AES128-GCM-SHA256"
  value = "true"
}

policy_attribute {
  name  = "Protocol-TLSv1.2"
  value = "true"
}
```

Alternatively, use a predefined security policy that enforces strong ciphers:

```hcl
policy_attribute {
  name  = "Reference-Security-Policy"
  value = "ELBSecurityPolicy-TLS-1-2-2017-01"
}
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "aws_elb" "negative1" {
  name               = "wu-tang"
  availability_zones = ["us-east-1a"]

  listener {
    instance_port      = 443
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = "arn:aws:iam::000000000000:server-certificate/wu-tang.net"
  }

  tags = {
    Name = "wu-tang"
  }
}

resource "aws_load_balancer_policy" "negative2" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ca-pubkey-policy"
  policy_type_name   = "PublicKeyPolicyType"

  policy_attribute {
    name  = "PublicKey"
    value = file("wu-tang-pubkey")
  }
}

resource "aws_load_balancer_policy" "negative3" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-root-ca-backend-auth-policy"
  policy_type_name   = "BackendServerAuthenticationPolicyType"

  policy_attribute {
    name  = "PublicKeyPolicyName"
    value = aws_load_balancer_policy.wu-tang-root-ca-pubkey-policy.policy_name
  }
}

resource "aws_load_balancer_policy" "negative4" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ssl"
  policy_type_name   = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "ECDHE-ECDSA-AES128-GCM-SHA256"
    value = "true"
  }

  policy_attribute {
    name  = "Protocol-TLSv1.2"
    value = "true"
  }
}

resource "aws_load_balancer_policy" "negative5" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ssl"
  policy_type_name   = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "Reference-Security-Policy"
    value = "ELBSecurityPolicy-TLS-1-1-2017-01"
  }
}

resource "aws_load_balancer_backend_server_policy" "negative6" {
  load_balancer_name = aws_elb.wu-tang.name
  instance_port      = 443

  policy_names = [
    aws_load_balancer_policy.wu-tang-root-ca-backend-auth-policy.policy_name,
  ]
}

resource "aws_load_balancer_listener_policy" "negative7" {
  load_balancer_name = aws_elb.wu-tang.name
  load_balancer_port = 443

  policy_names = [
    aws_load_balancer_policy.wu-tang-ssl.policy_name,
  ]
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_elb" "positive1" {
  name               = "wu-tang"
  availability_zones = ["us-east-1a"]

  listener {
    instance_port      = 443
    instance_protocol  = "http"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = "arn:aws:iam::000000000000:server-certificate/wu-tang.net"
  }

  tags = {
    Name = "wu-tang"
  }
}

resource "aws_load_balancer_policy" "positive2" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ca-pubkey-policy"
  policy_type_name   = "PublicKeyPolicyType"

  policy_attribute {
    name  = "PublicKey"
    value = file("wu-tang-pubkey")
  }
}

resource "aws_load_balancer_policy" "positive3" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-root-ca-backend-auth-policy"
  policy_type_name   = "BackendServerAuthenticationPolicyType"

  policy_attribute {
    name  = "PublicKeyPolicyName"
    value = aws_load_balancer_policy.wu-tang-root-ca-pubkey-policy.policy_name
  }
}

resource "aws_load_balancer_policy" "positive4" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ssl"
  policy_type_name   = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "Protocol-TLSv1.2"
    value = "true"
  }

  policy_attribute {
    name  = "TLS_RSA_ARCFOUR_128_SHA1"
    value = "true"
  }
}

resource "aws_load_balancer_policy" "positive5" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ssl"
  policy_type_name   = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "DES-CBC3-SHA"
    value = "true"
  }
}

resource "aws_load_balancer_policy" "positive6" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ssl"
  policy_type_name   = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
    value = "true"
  }
}

resource "aws_load_balancer_policy" "positive7" {
  load_balancer_name = aws_elb.wu-tang.name
  policy_name        = "wu-tang-ssl"
  policy_type_name   = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "Reference-Security-Policy"
    value = "ELBSecurityPolicy-TLS-1-1-2017-01"
  }
}

resource "aws_load_balancer_backend_server_policy" "positive8" {
  load_balancer_name = aws_elb.wu-tang.name
  instance_port      = 443

  policy_names = [
    aws_load_balancer_policy.wu-tang-root-ca-backend-auth-policy.policy_name,
  ]
}

resource "aws_load_balancer_listener_policy" "positive9" {
  load_balancer_name = aws_elb.wu-tang.name
  load_balancer_port = 443

  policy_names = [
    aws_load_balancer_policy.wu-tang-ssl.policy_name,
  ]
}


```