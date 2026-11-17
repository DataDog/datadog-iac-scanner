# Dockerfile rule model

Besides the legacy `command` and `args` fields, each Dockerfile document has a
`_dockerfile` model, so rules check facts instead of parsing Dockerfile syntax
or shell. BuildKit parses the Dockerfile and Tree-sitter Bash parses shell
scripts. Nothing is executed and no image is fetched.

## Model

| Field | Content |
| --- | --- |
| `instructions` | Every top-level instruction in order: `index`, `kind`, `stage`, `final_stage`, `first_of_kind_in_stage`, `last_of_kind_in_stage`, `context`, `source`, `parse_ok`, `error`, and its facts (see below). |
| `stages` | One per FROM: `name`, `base_stage` (index of a local base stage or -1), `from` (index of its FROM instruction), `origin_stage` (original external base), `context` (final context), `inherited_onbuild` (original ONBUILD instruction indices), `run_commands`, `source`. |
| `stage_names` | The BuildKit-normalized stage alias for each stage, aligned by index with `stages`; unnamed stages have an empty string. |
| `contexts` | Canonical effective configuration and binding state. Each instruction's `context` index selects the snapshot that applies when it runs: `user`, `user_name`, `user_set`, `user_instruction`, `workdir`, `shell`, `shell_known`, `healthcheck`, `healthcheck_set`, `environment_values`, `arguments` and `environment` binding frame indices, and `deferred` for ONBUILD triggers. Instructions can share a context. |
| `bindings`, `global_arguments` | ARG and ENV frames, each with a parent frame. |
| `resource_type`, `resource_name` | The resource that contract findings are reported on. |
| `contract_version` | Version of the parser-owned Dockerfile facts contract; currently `1`. |

Instruction facts: `image` and `platform` (FROM), `copy` (ADD, COPY), `bindings`
(ARG, ENV, LABEL), `value` or `values`, `mounts` (RUN), `healthcheck`,
`trigger` (ONBUILD, a nested instruction), `flags`, and `execution` (RUN, CMD,
ENTRYPOINT, HEALTHCHECK).

`final_stage` is true for top-level instructions whose `stage` is the last FROM
stage in the Dockerfile. Instructions before the first FROM and nested ONBUILD
triggers have it set to false. The fact is computed after the full Dockerfile
has been parsed.

`first_of_kind_in_stage` is true on the first top-level instruction of each
`kind` within its syntactic stage. Different kinds are tracked independently;
instructions before the first FROM are grouped by their kind. Nested ONBUILD
triggers are deferred child instructions and do not participate in the
top-level ordering fact.
`last_of_kind_in_stage` marks the last top-level instruction of the kind in
that stage; a single occurrence is both first and last.

`index` records an instruction's position in the top-level instruction array.
Nested ONBUILD triggers use `-1` because they are deferred and are not separate
source-file instructions.

Each stage's `run_commands` is a set-like inventory of command names from all
top-level RUN instructions in that syntactic stage. Names use the executable
basename, so `/usr/bin/wget` appears as `wget`. Deferred function bodies and
function invocations are excluded. Unknown executable names and incomplete
command inventories add an item with `known: false` internally; the policy
projection turns that item into an opaque open tail, including unknown
cardinality. Inherited ONBUILD RUN triggers also contribute an unknown tail.
The inventory does not describe ordering or include ordinary RUN commands from
a base stage or other instruction types. Stages with no RUN instructions or
inherited RUN triggers serialize `run_commands` as an empty array.
Instruction-scoped rules receive the selected stage's inventory as
`_dockerfile.stage_run_commands`; the full model stores it once on the stage.

Parser values have `value` and `known`, with optional `raw`, `references`,
`pattern` and a build-argument `default`. Defaults describe the default build,
not every possible caller-supplied build argument. An authored default remains
a reference value; it is not projected as a second resolved image that security
checks can substitute for an unresolved FROM reference.

Effective configuration lives once in the context table, rather than being
copied onto each instruction. `user_set` records a written or locally inherited
USER, and `user_instruction` identifies that instruction. `healthcheck_set`
separately records a local or locally inherited directive, so explicit-
configuration policies do not confuse syntactic absence with an unknown
external image setting. A local FROM inherits the parent stage's configuration.
HEALTHCHECK NONE explicitly disables an inherited check.

A local FROM conservatively accounts for the base stage's ONBUILD effects
before analyzing child instructions. Affected effective settings and source
provenance remain unknown until a child directive establishes them again.
Declaring and independent stages retain their facts; consumed triggers are not
re-exported automatically. Failed configuration instructions also invalidate
the affected state instead of reusing a stale setting. Deferred trigger
provenance and COPY relations into the downstream stage graph remain opaque.

Contexts also expose
`environment_values`, so rules do not resolve binding ancestry themselves.
External image configuration is not fetched: effective user, workdir, shell,
healthcheck and the environment map remain unknown where they cannot be
established locally. Unknown effective settings stay unknown at the rule
boundary, including reads that test their absence. The environment map is
conservatively opaque; explicit ENV bindings remain available on instructions.
The separate `user_set` and `healthcheck_set` facts describe observed directives;
they do not establish external image defaults.

## Commands

`execution` has `form` (`exec` or `shell`), `argv` or `script`, `shell`,
`shell_known`, and the facts of the command line:

`syntax` separately retains the Dockerfile-authored `form`, `argv` or `script`. It remains available if the engine represents semantic
`execution` facts as unknown.

- `calls`: each command run, with `name`, `arguments`, `wrappers` (such as
  `sudo` or `timeout`), `scope`, `guards` (`&&` and `||`), `conditional`,
  `deferred` (in a function body), `function` and `dynamic_arguments`.
  Calls in `sh -c` scripts are included.
- `package_commands`: package manager calls read with the manager's grammar:
  `manager`, `subcommand`, `action` (such as `install` for `apk add`), `options`,
  `packages` (`name`, `pinned`), `assume_yes` and `known`.
- `pipelines`, with `pipefail`; `scopes`.
- `success_predecessors` and `ordered_predecessors` on calls: scanner-computed
  command relationships. Ordering excludes pipelines and unrelated conditional
  branches. Rules do not reconstruct control flow.
- `complete` and `diagnostics`: unsupported syntax, dynamic scripts and limits
  make inventories partial. Known calls remain available.
- Heredoc shebangs and explicit interpreters select the grammar. Unsupported
  interpreters produce incomplete execution facts; they are not parsed as Bash.

RUN and HEALTHCHECK commands retain analyzed execution facts when their
interpreter is established locally. A shell-form command under an external base
image has an unknown inherited interpreter until an explicit SHELL, supported
heredoc interpreter, or locally inherited known SHELL establishes it. The engine
does not treat its parser fallback grammar as evidence of actual execution.
When that interpreter is unknown, the whole semantic `execution` object is
unknown; the authored command form and script remain available in `syntax`.
Exec-form CMD and
ENTRYPOINT retain their literal argv facts. Shell-form CMD and ENTRYPOINT keep
their script in `syntax` but mark semantic `execution`
facts incomplete; the scanner does not interpret image-runtime environment or
shell behavior as build-time facts.

## Normalized security inputs

The scanner decodes EXPOSE declarations into `ports` with numeric `start` and
`end` values, USER into effective `user_name`, and COPY `--from` into `from_kind`
(`index` or `name`). COPY stage sources resolve against all stages, including
forward references; FROM bases resolve only against earlier stages. Image facts include the normalized repository `namespace`;
ADD sources include their URL `scheme`. Shell calls expose a parsed `cd_path`
operand. These facts retain uncertainty when their source cannot be resolved.
Rego checks policy values and thresholds; it does not split Dockerfile or
command-line syntax to recover them. Package cache mount coverage is also a
scanner fact, including for apt list cleanup.

## Unknown values at the rule boundary

The engine makes an immutable, per-scan policy projection. Unknown values and
derived unknown facts use one random placeholder managed privately by the
engine. Rules and libraries do not inspect its encoding. Known absences remain absent.
Partial command inventories include the placeholder as an additional element.
Unknown argument positions cannot become known package actions or options.
The cardinality of an open inventory is unknown too, including when a rule uses
its count in arithmetic or compares it with another input. Count-dependent
findings are suppressed conservatively; the gate does not infer lower-bound
proofs from the known members. Unknown values inside fixed array/object slots
do not by themselves change the number of slots.
Parser-only `known`, `complete`, `shell_known`, `version_known` and `parse_ok`
fields, instruction parse diagnostics, context uncertainty flags and unknown
binding-frame markers are consumed by this projection and omitted from Rego.
Recovered independent facts remain available after partial parsing; missing
semantic facts and incomplete inventories become opaque.

An unresolved FROM may select an earlier local stage. Its base/origin links,
unwritten inherited configuration, and environment map therefore remain
unknown at the policy boundary. Shared contexts are copied before tainting,
so independent stages retain their known facts. Shell-form commands whose
inherited interpreter cannot be established have unknown execution
inventories; explicit SHELL directives and exec-form commands retain their
independent facts. Syntax facts such as instruction kind and execution form
remain available.

By default, contract rules that call `data.generic.common.finding` evaluate
each Dockerfile as an independent build root, with all its stages together. This
keeps unrelated builds from combining facts or uncertainty. Legacy rules keep
their combined input.

A rule that checks one instruction can declare an instruction unit with an OPA
package annotation:

```rego
# METADATA
# scope: package
# custom:
#   datadog:
#     dockerfile:
#       version: 1
#       scope: instruction
#       kinds: [run]
package datadog
```

When `scope: instruction` omits `kinds`, every top-level instruction is
selected, including instructions with a kind introduced by a future parser
version. When present, `kinds` must be a non-empty list of supported kind
names; an explicit empty or null list is invalid.

Each selected instruction is then a separate input document. That document
contains its original `id`, resource identity, and only the selected instruction
under `_dockerfile.instructions`. The instruction keeps its original native
node IDs and source positions. Other instructions, document-level stages,
context/binding arrays and legacy fields are outside this declared unit. The
selected instruction includes its intrinsic parser facts and its context
index, but no copied context snapshot. Rules that depend on effective config,
other instructions, stages, contexts or bindings must use a stage unit where
its typed relations suffice, or the full Dockerfile unit. This declaration is
part of the rule's semantics, rather than a smaller certainty-check input for
a file-wide rule. The unknown gate checks the
complete input of each unit. File-wide rules use the full Dockerfile model,
including all instructions, stages, contexts and bindings.

A configuration check can instead declare `scope: stage` (without `kinds`).
Each stage is then evaluated with a fixed semantic unit under `_dockerfile`:

| Field | Meaning |
| --- | --- |
| `stage` | The complete stage record, including its native identity and command inventory. |
| `context` | Its canonical final context, with unresolved effective settings preserved as unknown. |
| `from` | The complete FROM instruction that declares this stage; `from.final_stage` identifies the final stage. |
| `origin_from` | The complete original external FROM instruction, or an unknown relation when its provenance is unresolved. |
| `user_instruction` | The complete local USER instruction that supplied the effective user, `null` when no local source was observed, or an unknown relation when its provenance is unresolved. |

Source indices and node identities retain their original file positions.
Stage and instruction units are fixed schemas, not author-selected field
views. The gate checks their complete inputs. A stage unit preserves all stage
and context facts and the relations above; a rule needing other instructions,
binding tables or cross-stage traversal uses the full Dockerfile scope.

## Contract version

Native Dockerfile rules declare the contract version at package scope with
`custom.datadog.dockerfile.version: 1`. The `generic.dockerfile` library declares
the same version, and parser documents include `contract_version: 1`. The library
uses the engine capability `data.datadog_scanner.dockerfile_v1(1)` through
the Dockerfile library. Scanners that do not provide that capability fail to
compile the rule or library, preventing a policy from silently running against
an older fact model. The engine also checks the rule, library and model
versions before accepting contract findings.

Before decoding contract findings, the engine uses the shared
`pkg/engine/unknowngate` gate to suppress findings whose verdict depends on
unknown values. After tracing an independent derivation, the Dockerfile engine
can certify the complete rule output through OPA partial evaluation with every
opaque input left unknown. Certification requires an unconditional result with
no residual or saved expressions, supporting modules or builtin errors.
Otherwise, the existing substitution checks run unchanged. This optimization
uses the complete evaluation unit and immutable data; it does not select fields
or reduce the uncertainty scope. Known independent findings remain reportable.
A gate failure retracts the query's results rather than reporting unchecked
findings. Cancellation aborts the scan. Debug logs include candidate,
suppression and certification counts.

Rules and platform helpers treat unknown values as opaque. They must not
inspect `known`, `complete`, or placeholder metadata to decide whether a finding
should be suppressed. The shared engine gate owns that decision. Parser-only status and diagnostics,
including `parse_ok`, stay outside the policy input.

`execution.package_cache_mounts` holds a boolean fact for each shell call index
(`command.call`): whether cache mounts cover the package manager's cache paths.
Non-package calls have null entries. The scanner resolves a literal manager
cache option only when no other manager options can affect its path, or an
explicitly set Dockerfile cache ENV when the command has no options. Defaults,
unmodeled option combinations, uncertain paths, and shell environment changes
remain unknown. Failed mount-option expansion leaves an open mount inventory
and unknown coverage; a successfully parsed empty mount list remains known
and empty. An unknown is never encoded as a successful cache mount. Rego
only checks the resulting `value`.

Helpers must preserve unknowns, including when negating an absence check. Do
not replace an unknown with false, an empty string, or an empty collection.
The gate is conservative and can suppress certain findings when it cannot
establish an independent derivation. Legacy searchKey rules and their
`command` / `args` data retain their previous behavior.

## Locations

Instructions, stages, calls, pipelines, package commands and packages have a
`source`: `line` and `end_line` are one-based, `column` and `end_column` are
zero-based byte offsets with an exclusive end. Calls in nested scripts and
ONBUILD triggers have no source of their own.

The engine stamps reportable nodes with `_dd_meta.id`; Rego helpers return
these nodes without copying their unknown-bearing contents. A contract finding
names a node rather than giving a search key. Its `_dd_id` is `<document id>#<JSON pointer>` and its `path` descends from that node. The
Dockerfile detector rebuilds the model and reports the finding at the deepest
`source` on the way to the node.

```rego
some document in docker.files
some instruction in document._dockerfile.instructions
some command in instruction.execution.package_commands
command.action == "install"
some i, pkg in command.packages
pkg.pinned == false
result := common.finding(command._dd_meta.id, ["packages", i], {})
```

The CI/CD rules still use the legacy `Parse` projection of the shell package.
