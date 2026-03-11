---
title: "Cloud Storage Anonymous or Publicly Accessible"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cloud_storage_anonymous_or_publicly_accessible"
  id: "086031e1-9d4a-4249-acb3-5bfe4c363db2"
  display_name: "Cloud Storage Anonymous or Publicly Accessible"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `086031e1-9d4a-4249-acb3-5bfe4c363db2`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_storage_bucket_module.html)

### Description

Cloud Storage buckets must not be anonymously or publicly accessible because setting an ACL entity to 'allUsers' or 'allAuthenticatedUsers' grants broad read or write access to anyone on the internet or to any authenticated Google account, risking data exposure or unauthorized modification. For Ansible `gcp_storage_bucket` resources (modules `google.cloud.gcp_storage_bucket` and `gcp_storage_bucket`), ensure neither the `acl.entity` nor the `default_object_acl.entity` property is set to `allUsers` or `allAuthenticatedUsers`. If a bucket does not define `acl`, `default_object_acl` must be explicitly defined and must not contain those public entities; tasks missing `default_object_acl` or with either entity set to `allUsers`/`allAuthenticatedUsers` will be flagged.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create a bucket
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    acl:
      bucket: bucketName
      entity: group-example@googlegroups.com

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create a bucket1
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    default_object_acl:
      bucket: bucketName1
      entity: allUsers
      role: READER
- name: create a bucket2
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module2
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    acl:
      bucket: bucketName2
      entity: allAuthenticatedUsers
    default_object_acl:
      bucket: bucketName2
      entity: allUsers
      role: READER
- name: create a bucket3
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module3
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```