---
title: "npm install command without pinned version"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/npm_install_without_pinned_version"
  id: "e36d8880-3f78-4546-b9a1-12f0745ca0d5"
  display_name: "npm install command without pinned version"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `e36d8880-3f78-4546-b9a1-12f0745ca0d5`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

Installing packages without pinned versions risks unintentional or malicious dependency upgrades, leading to supply-chain compromises, newly introduced vulnerabilities, or non-reproducible builds.

This rule inspects `run` command entries that invoke `npm install`, `npm i`, or `npm add` and requires each package argument (excluding command flags) to include an explicit version or tag (for example, `package@1.2.3` or `@scope/pkg@^1.2.3`) or be a git-based reference (for example, `git+https://...`). Tokens that start with `-` (npm flags) are allowed. Scoped packages must still include a version suffix and bare package names without an `@version` will be flagged. 

Secure example with pinned versions:

```json
{
  "scripts": {
    "install-deps": "npm install express@4.17.1 lodash@4.17.21 @scope/pkg@1.2.3"
  }
}
```

## Compliant Code Examples
```dockerfile
FROM node:12
RUN npm install
RUN npm install sax@latest
RUN npm install sax@0.1.1
RUN npm install sax@0.1.1 | grep fail && npm install sax@latest
RUN npm install git://github.com/npm/cli.git
RUN npm install git+ssh://git@github.com:npm/cli#semver:^5.0
RUN npm install --production --no-cache
RUN npm config set registry <internal_npm_registry> && \
    npm install && \
    npx vite build --mode $VITE_MODE
```
## Non-Compliant Code Examples
```dockerfile
FROM node:12
RUN npm install sax
RUN npm install sax --no-cache
RUN npm install sax | grep fail && npm install sax@latest
RUN npm install sax@latest | grep fail && npm install sax
RUN npm install sax | grep fail && npm install sax
RUN npm i -g @angular/cli
RUN ["npm","add","sax"]

```