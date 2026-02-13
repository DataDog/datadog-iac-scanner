---
title: "Wildcard in ACM certificate domain name"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/wildcard_in_acm_certificate_domain_name"
  id: "cc8b294f-006f-4f8f-b5bb-0a9140c33131"
  display_name: "Wildcard in ACM certificate domain name"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `cc8b294f-006f-4f8f-b5bb-0a9140c33131`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html)

### Description

 Using a bare wildcard (`*`) as an ACM certificate `DomainName` creates overly broad trust and can enable certificate issuance or use that is not tied to a specific domain. This increases the risk of impersonation and unauthorized TLS termination.

For `AWS::CertificateManager::Certificate` resources, `Properties.DomainName` must be a valid domain or a properly scoped wildcard subdomain (for example, `example.com` or `*.example.com`) and must not be the single character `*`. Resources where `DomainName` is exactly `*` will be flagged. Use explicit hostnames or scoped wildcard names and, if you need multiple names, list them in `SubjectAlternativeNames` rather than using a universal wildcard.

Secure configuration example:

```yaml
MyCertificate:
  Type: AWS::CertificateManager::Certificate
  Properties:
    DomainName: www.example.com
    ValidationMethod: DNS
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainName:
    Description: "Domain for which you are requesting a cert"
    Type: String
    Default: example.com #Put your own domain name here
  HostedZoneId:
    Description: "hosted zone id in which CNAME record for the validation needs to be added"
    Type: String
    Default: XYZABCDERYH #Put the hosted zone id in which CNAME record for the validation needs to be added

Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: CMDomain
      DomainValidationOptions:
        - DomainName: !Ref DomainName
          HostedZoneId: !Ref HostedZoneId
      ValidationMethod: 'DNS'
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "DomainName": {
      "Type": "String",
      "Default": "example.com",
      "Description": "Domain for which you are requesting a cert"
    },
    "HostedZoneId": {
      "Description": "hosted zone id in which CNAME record for the validation needs to be added",
      "Type": "String",
      "Default": "XYZABCDERYH"
    }
  },
  "Resources": {
    "Certificate": {
      "Type": "AWS::CertificateManager::Certificate",
      "Properties": {
        "DomainName": "CMDomain",
        "DomainValidationOptions": [
          {
            "HostedZoneId": "HostedZoneId",
            "DomainName": "DomainName"
          }
        ],
        "ValidationMethod": "DNS"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "HostedZoneId": {
      "Type": "String",
      "Default": "XYZABCDERYH",
      "Description": "hosted zone id in which CNAME record for the validation needs to be added"
    },
    "DomainName": {
      "Description": "Domain for which you are requesting a cert",
      "Type": "String",
      "Default": "example.com"
    }
  },
  "Resources": {
    "Certificate": {
      "Type": "AWS::CertificateManager::Certificate",
      "Properties": {
        "DomainName": "*",
        "DomainValidationOptions": [
          {
            "DomainName": "DomainName",
            "HostedZoneId": "HostedZoneId"
          }
        ],
        "ValidationMethod": "DNS"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainName:
    Description: "Domain for which you are requesting a cert"
    Type: String
    Default: example.com #Put your own domain name here
  HostedZoneId:
    Description: "hosted zone id in which CNAME record for the validation needs to be added"
    Type: String
    Default: XYZABCDERYH #Put the hosted zone id in which CNAME record for the validation needs to be added

Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: "*"
      DomainValidationOptions:
        - DomainName: !Ref DomainName
          HostedZoneId: !Ref HostedZoneId
      ValidationMethod: 'DNS'
```