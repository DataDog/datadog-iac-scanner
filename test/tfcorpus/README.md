# The Terraform fixture corpus

This package generates the Terraform scan fixtures the general property
tests run over: every cell combines an indirection (a variable, a local, a
module output, a data source, a try, ...), a value shape, the way a probe
rule reads it, where the value originates, an unknown value the finding
does not depend on, and a polarity. The expansion grid adds counted,
for_each and module sinks; the attribute-state grid adds the ways an
attribute can be written.

The generated probe rules fire exactly on a cell's firing value, so each
cell carries its own literal oracle: what the evaluator resolves the
indirection to, after the unknown gate decides what is certain.

## Ephemeral blocks

The engine currently does not expand ephemeral blocks: they are evaluated
as written, so an ephemeral block with count or for_each keeps one unkeyed
instance. The ephemeral parity cells therefore intentionally cover the
singleton case only, and they do not test multi-instance parity. Expanding
ephemeral blocks is engine work outside the scope of this corpus.

## Regenerating the goldens

The legacy-document goldens live in
`../tfproperties/testdata/legacy_golden`; their README describes how to
produce them from another engine build.
