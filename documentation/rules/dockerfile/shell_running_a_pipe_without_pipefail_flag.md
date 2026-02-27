---
title: "Shell running a pipe without the pipefail flag"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/shell_running_a_pipe_without_pipefail_flag"
  id: "efbf148a-67e9-42d2-ac47-02fa1c0d0b22"
  display_name: "Shell running a pipe without the pipefail flag"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `efbf148a-67e9-42d2-ac47-02fa1c0d0b22`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

Pipeline commands executed by POSIX shells must enable the `pipefail` option so that a failure in any stage of a pipeline makes the whole command fail. Without `pipefail`, earlier command failures can be masked and CI/build steps or image contents may be left in an inconsistent or insecure state.

This check targets Dockerfile-style instructions: `RUN` commands that invoke a shell (bash, zsh, ash, /bin/bash, /bin/zsh, /bin/ash) and contain a pipe character (`|`) must have `pipefail` enabled either via a preceding `SHELL` instruction that includes `-o pipefail` or by enabling it in the `RUN` command itself. Resources will be flagged when a `RUN` with a pipeline is present and there is no prior `SHELL` instruction with `-o pipefail` and the `RUN` does not explicitly enable `pipefail`. PowerShell-style commands are excluded. Fixes include setting a global shell with pipefail or prefixing pipeline commands with `set -o pipefail` (see examples below).

Secure configuration with a global `SHELL` in a Dockerfile:

```dockerfile
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN command1 | command2
```

Secure inline option for a single `RUN`:

```dockerfile
RUN set -o pipefail; command1 | command2
```

## Compliant Code Examples
```dockerfile
FROM node:12
RUN pwsh SOME_CMD | SOME_OTHER_CMD
SHELL [ "zsh", "-o","pipefail" ]
RUN zsh ./some_output | ./some_script
SHELL [ "/bin/bash", "-o","pipefail" ]
RUN [ "/bin/bash", "./some_output", "./some_script" ]


```
## Non-Compliant Code Examples
```dockerfile
FROM node:12
RUN zsh ./some_output | ./some_script
RUN [ "/bin/bash", "./some_output", "|", "./some_script" ]
```