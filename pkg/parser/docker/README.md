# Dockerfile rule model

Besides the legacy `command` and `args` fields, each Dockerfile document has a
`_dockerfile` model, so rules check facts instead of parsing Dockerfile syntax
or shell. BuildKit parses the Dockerfile and Tree-sitter Bash parses shell
scripts. Nothing is executed and no image is fetched.

## Model

| Field | Content |
| --- | --- |
| `instructions` | Every instruction in order: `kind`, `stage`, `context`, `source`, `parse_ok`, `error`, and its facts (see below). |
| `stages` | One per FROM: `name`, `base_stage` (index of a local base stage or -1), `from` (index of its FROM instruction), `context` (final context), `source`. |
| `contexts` | What applies when an instruction runs: `user`, `workdir`, `arguments` and `environment` (binding frame indices, -1 when unknown), `deferred` for ONBUILD triggers. Instructions share them. |
| `bindings`, `global_arguments` | ARG and ENV frames, each with a parent frame. |
| `resource_type`, `resource_name` | The resource that contract findings are reported on. |

Instruction facts: `image` and `platform` (FROM), `copy` (ADD, COPY), `bindings`
(ARG, ENV, LABEL), `value` or `values`, `mounts` (RUN), `healthcheck`,
`trigger` (ONBUILD, a nested instruction), `flags`, and `execution` (RUN, CMD,
ENTRYPOINT, HEALTHCHECK).

A value has `value` and `known`. Use `value` only when `known` is true. It may
also have `raw`, `references`, `pattern` and a build-argument `default`.

## Commands

`execution` has `form` (`exec` or `shell`), `argv` or `script`, `shell`,
`shell_known`, and the facts of the command line:

- `calls`: each command run, with `name`, `arguments`, `wrappers` (such as
  `sudo` or `timeout`), `scope`, `guards` (`&&` and `||`), `conditional`,
  `deferred` (in a function body), `function` and `dynamic_arguments`.
  Calls in `sh -c` scripts are included.
- `package_commands`: package manager calls read with the manager's grammar:
  `manager`, `subcommand`, `action` (such as `install` for `apk add`), `options`,
  `packages` (`name`, `pinned`), `assume_yes` and `known`.
- `pipelines`, with `pipefail`; `scopes`.
- `complete` and `diagnostics`. A rule that asserts that something is absent
  must require `complete`, since unsupported syntax, dynamic scripts and limits
  make the facts partial.

## Locations

Instructions, stages, calls, pipelines, package commands and packages have a
`source`: `line` and `end_line` are one-based, `column` and `end_column` are
zero-based byte offsets with an exclusive end. Calls in nested scripts and
ONBUILD triggers have no source of their own.

A contract finding names a node rather than giving a search key. Its `_dd_id`
is `<document id>#<JSON pointer>` and its `path` descends from that node. The
Dockerfile detector rebuilds the model and reports the finding at the deepest
`source` on the way to the node.

```rego
some instruction in document._dockerfile.instructions
some command in instruction.execution.package_commands
command.action == "install"
some package in command.packages
not package.pinned
```

The CI/CD rules still use the legacy `Parse` projection of the shell package.
