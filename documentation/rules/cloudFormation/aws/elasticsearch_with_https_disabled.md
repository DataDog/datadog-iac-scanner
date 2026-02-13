---
title: "Elasticsearch with HTTPS disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elasticsearch_with_https_disabled"
  id: "4cdc88e6-c0c8-4081-a639-bb3a557cbedf"
  display_name: "Elasticsearch with HTTPS disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `4cdc88e6-c0c8-4081-a639-bb3a557cbedf`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html)

### Description

Domain endpoints for Elasticsearch/OpenSearch must enforce HTTPS to protect data in transit and prevent interception or tampering of requests and responses.
 
 For CloudFormation resources of type `AWS::Elasticsearch::Domain` and `AWS::OpenSearchService::Domain`, the `DomainEndpointOptions.EnforceHTTPS` property must be defined and set to `true`. Resources missing `DomainEndpointOptions`, missing `EnforceHTTPS`, or with `EnforceHTTPS` set to `false` will be flagged.

Secure configuration example:

```yaml
MyDomain:
  Type: AWS::OpenSearchService::Domain
  Properties:
    DomainName: my-domain
    DomainEndpointOptions:
      EnforceHTTPS: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: description
Resources:
  OpenSearchDomain:
    Type: AWS::OpenSearchService::Domain
    Properties:
      DomainName: my-opensearch-domain
      ElasticsearchVersion: "7.9"
      ElasticsearchClusterConfig:
        InstanceType: m5.large.search
        InstanceCount: 1
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"
      DomainEndpointOptions:
        EnforceHTTPS: true
        TLSSecurityPolicy: "Policy-Min-TLS-1-2-2019-07"

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: description
Resources:
  ElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: my-elasticsearch-domain
      ElasticsearchVersion: "7.9"
      ElasticsearchClusterConfig:
        InstanceType: m5.large.elasticsearch
        InstanceCount: 1
      EBSOptions:
        EBSEnabled: true
        VolumeType: gp2
        VolumeSize: 10
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "*"
            Action: es:*
            Resource: arn:aws:es:REGION:ACCOUNT_ID:domain/my-elasticsearch-domain/*
      DomainEndpointOptions:
        TLSSecurityPolicy: "Policy-Min-TLS-1-2-2019-07"

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: description
Resources:
  ElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: my-elasticsearch-domain
      ElasticsearchVersion: "7.9"
      ElasticsearchClusterConfig:
        InstanceType: m5.large.elasticsearch
        InstanceCount: 1
      EBSOptions:
        EBSEnabled: true
        VolumeType: gp2
        VolumeSize: 10
      AccessPolicies:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "*"
            Action: es:*
            Resource: arn:aws:es:REGION:ACCOUNT_ID:domain/my-elasticsearch-domain/*

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: description
Resources:
  OpenSearchDomain:
    Type: AWS::OpenSearchService::Domain
    Properties:
      DomainName: my-opensearch-domain
      ElasticsearchVersion: "7.9"
      ElasticsearchClusterConfig:
        InstanceType: m5.large.search
        InstanceCount: 1
      AdvancedOptions:
        rest.action.multi.allow_explicit_index: "true"
      DomainEndpointOptions:
        EnforceHTTPS: false
        TLSSecurityPolicy: "Policy-Min-TLS-1-2-2019-07"

```