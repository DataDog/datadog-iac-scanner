---
title: "COPY with more than two arguments not ending with a slash"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/copy_with_more_than_two_arguments_not_ending_with_slash"
  id: "6db6e0c2-32a3-4a2e-93b5-72c35f4119db"
  display_name: "COPY with more than two arguments not ending with a slash"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `6db6e0c2-32a3-4a2e-93b5-72c35f4119db`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#copy)

### Description

`COPY` commands that reference a storage path must end directory arguments with a trailing slash so the command targets the intended directory prefix rather than a single object. Omitting the slash can lead to ambiguous file selection and accidental inclusion or exclusion of files, causing data integrity problems or unintended data exposure.

This check inspects `COPY` commands with more than two arguments and verifies that the final argument (the source path) ends with a `/` character. Resources where the command has more than two elements and the last element does not end with `/` will be flagged. Ensure the source path is explicitly a directory by including the trailing slash. For example:

```
COPY INTO my_table FROM 's3://my-bucket/path/' CREDENTIALS=...;
```

## Compliant Code Examples
```dockerfile
FROM node:carbon1
COPY package.json yarn.lock

```

```dockerfile
FROM node:carbon
COPY package.json yarn.lock my_app/

```
## Non-Compliant Code Examples
```dockerfile
FROM node:carbon2
COPY package.json yarn.lock my_app

```