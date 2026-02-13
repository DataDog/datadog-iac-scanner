---
title: "AWS DMS replication instance is publicly accessible"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/amazon_dms_replication_instance_is_publicly_accessible"
  id: "5864fb39-d719-4182-80e2-89dbe627be63"
  display_name: "AWS DMS replication instance is publicly accessible"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `5864fb39-d719-4182-80e2-89dbe627be63`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html)

### Description

 AWS DMS replication instances must not be publicly accessible because exposing the instance and its endpoints to the internet increases the risk of unauthorized access and data exfiltration. In CloudFormation, the `PubliclyAccessible` property on `AWS::DMS::ReplicationInstance` resources must be defined and set to `false`; resources with `PubliclyAccessible` set to `true` or missing the property will be flagged. Place replication instances in private subnets and ensure associated security groups and subnet groups restrict inbound access to trusted networks or management hosts.  

Secure CloudFormation example:

```yaml
MyDmsReplicationInstance:
  Type: AWS::DMS::ReplicationInstance
  Properties:
    ReplicationInstanceIdentifier: my-dms-instance
    ReplicationInstanceClass: dms.t3.medium
    PubliclyAccessible: false
    # other required properties...
```


## Compliant Code Examples
```yaml
Resources:
  ReplicationInstance:
    Type: "AWS::DMS::ReplicationInstance"
    Properties:
      ReplicationInstanceIdentifier: my-replication-instance
      ReplicationInstanceClass: dms.r5.large
      AllocatedStorage: 100
      EngineVersion: "3.4.3"
      PubliclyAccessible: false

```
## Non-Compliant Code Examples
```yaml
Resources:
  ReplicationInstance:
    Type: "AWS::DMS::ReplicationInstance"
    Properties:
      ReplicationInstanceIdentifier: my-replication-instance
      ReplicationInstanceClass: dms.r5.large
      AllocatedStorage: 100
      EngineVersion: "3.4.3"

```

```yaml
Resources:
  ReplicationInstance:
    Type: "AWS::DMS::ReplicationInstance"
    Properties:
      ReplicationInstanceIdentifier: my-replication-instance
      ReplicationInstanceClass: dms.r5.large
      AllocatedStorage: 100
      EngineVersion: "3.4.3"
      PubliclyAccessible: true

```