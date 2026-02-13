---
title: "Route53 record undefined"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/route53_record_undefined"
  id: "24d932e1-91f0-46ea-836f-fdbd81694151"
  display_name: "Route53 record undefined"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `24d932e1-91f0-46ea-836f-fdbd81694151`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html)

### Description

A Route 53 hosted zone without any DNS record sets can lead to service outages from missing DNS entries. It also increases the risk of unmanaged or manual record additions that bypass infrastructure-as-code controls.

In CloudFormation, every `AWS::Route53::HostedZone` should be accompanied by one or more `AWS::Route53::RecordSet` resources. Record sets should reference the hosted zone via `HostedZoneId` or `HostedZoneName`, and define `Name` and `Type` (plus appropriate record data such as `TTL` and `ResourceRecords`. Templates that create an `AWS::Route53::HostedZone` but contain no `AWS::Route53::RecordSet` resources in the same template will be flagged.

Secure example referencing the hosted zone ID:

```yaml
MyHostedZone:
  Type: AWS::Route53::HostedZone
  Properties:
    Name: example.internal

MyRecordSet:
  Type: AWS::Route53::RecordSet
  Properties:
    HostedZoneId: !Ref MyHostedZone
    Name: service.example.internal.
    Type: A
    TTL: '300'
    ResourceRecords:
      - 10.0.0.10
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"
  RecordSet:
    Type: AWS::Route53::RecordSet
    Properties:
      HostedZoneId: !Ref HostedZoneId
      Name: !Join ['', [!Ref DomainName, '.', !Ref HostedZoneName, '.']]
      Type: CNAME
      TTL: '900'
      ResourceRecords:
      - !Ref DnsEndpoint

```

```json
{
  "Description": "Router53",
  "Resources": {
    "HostedZone": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "HostedZone"
      }
    },
    "RecordSet": {
      "Type": "AWS::Route53::RecordSet",
      "Properties": {
        "HostedZoneId": "HostedZoneId",
        "Name": [
          "",
          [
            "DomainName",
            ".",
            "HostedZoneName",
            "."
          ]
        ],
        "Type": "CNAME",
        "TTL": "900",
        "ResourceRecords": [
          "DnsEndpoint"
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Router53",
  "Resources": {
    "HostedZone": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "HostedZone"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"

```