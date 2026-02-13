---
title: "Disk encryption disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/disk_encryption_disabled"
  id: "b1d51728-7270-4991-ac2f-fc26e2695b38"
  display_name: "Disk encryption disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `b1d51728-7270-4991-ac2f-fc26e2695b38`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk)

### Description

Critical virtual machine disks in Google Cloud should be encrypted with Customer Supplied Encryption Keys (CSEK) or Customer-Managed Encryption Keys (CMEK) to ensure the security of sensitive data at rest. If the `disk_encryption_key` block is missing or does not include either the `raw_key` or `kms_key_self_link` attributes, disks remain encrypted only with Google-managed keys. This may not meet data residency or compliance requirements and could expose data if the default encryption keys are compromised. To address this, you should define the `disk_encryption_key` with either a CSEK or CMEK, for example:

```
resource "google_compute_disk" "secure_example" {
  name  = "secure-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "prod"
  }
  physical_block_size_bytes = 4096

  disk_encryption_key {
    raw_key = "SGVsbG8gZnJvbSBHb29nbGUgQ2xvdWQgUGxhdGZvcm0=" // CSEK
    sha256  = "A"
  }
}
```
Unencrypted disks can lead to unauthorized disclosure of sensitive information or regulatory compliance violations if left unaddressed.

## Compliant Code Examples
```terraform
resource "google_compute_disk" "negative1" {
  name  = "test-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096

  disk_encryption_key {
      kms_key_self_link = "disk-crypto-key"
      sha256 = "A"
  }
}

```

```terraform
resource "google_compute_disk" "negative1" {
  name  = "test-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096

  disk_encryption_key {
      raw_key = "SGVsbG8gZnJvbSBHb29nbGUgQ2xvdWQgUGxhdGZvcm0="
      sha256 = "A"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_disk" "positive3" {
  name  = "test-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096

  disk_encryption_key {
      raw_key = ""
      sha256 = "A"
  }
}

```

```terraform
resource "google_compute_disk" "positive4" {
  name  = "test-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096

  disk_encryption_key {
    kms_key_self_link = ""
    sha256 = "A"
  }
}

```

```terraform
resource "google_compute_disk" "positive1" {
  name  = "test-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096
}

resource "google_compute_disk" "positive2" {
  name  = "test-disk"
  type  = "pd-ssd"
  zone  = "us-central1-a"
  image = "debian-9-stretch-v20200805"
  labels = {
    environment = "dev"
  }
  physical_block_size_bytes = 4096

  disk_encryption_key {
    sha256 = "A"
  }
}

```