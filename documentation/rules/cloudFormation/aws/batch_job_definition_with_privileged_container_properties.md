---
title: "Batch job definition with privileged container properties"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/batch_job_definition_with_privileged_container_properties"
  id: "76ddf32c-85b1-4808-8935-7eef8030ab36"
  display_name: "Batch job definition with privileged container properties"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `76ddf32c-85b1-4808-8935-7eef8030ab36`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-batch-jobdefinition.html)

### Description

 Running Batch job containers in privileged mode grants them elevated access to the host kernel and device nodes, which can enable container escape, host compromise, and lateral movement across your environment. The `Privileged` property under `Properties.ContainerProperties` in `AWS::Batch::JobDefinition` must be set to `false`. Resources with `Privileged` set to `true` will be flagged. If a job legitimately requires extra capabilities, avoid privileged mode and instead grant only the specific capabilities needed or run the workload on dedicated, hardened hosts.

Secure configuration example:

```yaml
MyJobDefinition:
  Type: AWS::Batch::JobDefinition
  Properties:
    ContainerProperties:
      Image: my-image
      Vcpus: 1
      Memory: 1024
      Privileged: false
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
Resources:
  JobDefinition:
    Type: AWS::Batch::JobDefinition
    Properties:
      Type: container
      JobDefinitionName: nvidia-smi
      ContainerProperties:
        MountPoints:
          - ReadOnly: false
            SourceVolume: nvidia
            ContainerPath: /usr/local/nvidia
        Volumes:
          - Host:
              SourcePath: /var/lib/nvidia-docker/volumes/nvidia_driver/latest
            Name: nvidia
        Command:
          - nvidia-smi
        Memory: 2000
        Privileged: false
        JobRoleArn: String
        ReadonlyRootFilesystem: true
        Vcpus: 2
        Image: nvidia/cuda


```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "BatchJobDefinition",
  "Resources": {
    "JobDefinition1": {
      "Type": "AWS::Batch::JobDefinition",
      "Properties": {
        "Type": "container",
        "JobDefinitionName": "nvidia-smi",
        "ContainerProperties": {
          "Memory": 2000,
          "JobRoleArn": "String",
          "ReadonlyRootFilesystem": true,
          "Vcpus": 2,
          "Image": "nvidia/cuda",
          "MountPoints": [
            {
              "SourceVolume": "nvidia",
              "ContainerPath": "/usr/local/nvidia",
              "ReadOnly": false
            }
          ],
          "Volumes": [
            {
              "Host": {
                "SourcePath": "/var/lib/nvidia-docker/volumes/nvidia_driver/latest"
              },
              "Name": "nvidia"
            }
          ],
          "Command": [
            "nvidia-smi"
          ]
        }
      }
    }
  }
}

```

```yaml


AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
Resources:
  JobDefinition1:
    Type: AWS::Batch::JobDefinition
    Properties:
      Type: container
      JobDefinitionName: nvidia-smi
      ContainerProperties:
        MountPoints:
          - ReadOnly: false
            SourceVolume: nvidia
            ContainerPath: /usr/local/nvidia
        Volumes:
          - Host:
              SourcePath: /var/lib/nvidia-docker/volumes/nvidia_driver/latest
            Name: nvidia
        Command:
          - nvidia-smi
        Memory: 2000
        JobRoleArn: String
        ReadonlyRootFilesystem: true
        Vcpus: 2
        Image: nvidia/cuda

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "BatchJobDefinition",
  "Resources": {
    "JobDefinition": {
      "Type": "AWS::Batch::JobDefinition",
      "Properties": {
        "Type": "container",
        "JobDefinitionName": "nvidia-smi",
        "ContainerProperties": {
          "Memory": 2000,
          "Privileged": true,
          "Vcpus": 2,
          "MountPoints": [
            {
              "ReadOnly": false,
              "SourceVolume": "nvidia",
              "ContainerPath": "/usr/local/nvidia"
            }
          ],
          "Command": [
            "nvidia-smi"
          ],
          "ReadonlyRootFilesystem": true,
          "Image": "nvidia/cuda",
          "Volumes": [
            {
              "Host": {
                "SourcePath": "/var/lib/nvidia-docker/volumes/nvidia_driver/latest"
              },
              "Name": "nvidia"
            }
          ],
          "JobRoleArn": "String"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "BatchJobDefinition"
Resources:
  JobDefinition:
    Type: AWS::Batch::JobDefinition
    Properties:
      Type: container
      JobDefinitionName: nvidia-smi
      ContainerProperties:
        MountPoints:
          - ReadOnly: false
            SourceVolume: nvidia
            ContainerPath: /usr/local/nvidia
        Volumes:
          - Host:
              SourcePath: /var/lib/nvidia-docker/volumes/nvidia_driver/latest
            Name: nvidia
        Command:
          - nvidia-smi
        Memory: 2000
        Privileged: true
        JobRoleArn: String
        ReadonlyRootFilesystem: true
        Vcpus: 2
        Image: nvidia/cuda

```