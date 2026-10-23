# Terraform instance scanning

Terraform and OpenTofu configurations (`.tf`, `.tf.json`, `.tofu`, and
`.tofu.json`) expand resource, data, and module declarations with known `count`
or `for_each` values. Bodies evaluate with `count.index`, `each.key`, and
`each.value` bound for that instance. Supported configuration-only data sources
expose counted results as tuples and keyed results as objects, including empty
collections, so instance-specific references can resolve before rule evaluation.

The plain parser emits **document layers**, rather than isolated documents for
each resource. The first layer contains every declared block's first distinct
instance; subsequent layers replace expanded blocks with their next distinct
values. Blocks with fewer distinct values retain their first value in later
layers. Layers share unchanged subtrees and retain the original block names and
line tables, keeping the file's other resources available to rules. This is a
bounded set of views of the file, not a Cartesian product of all instances.
Identical converted instances share a view. Findings repeated across layers
are removed only when their report evidence and provenance are identical.

Expansion uses the shared resolver's limit of 50 instances per block, with
5,000 additional block conversions per file. A truncated block also gets an
as-written view for the unexpanded tail; an unresolved or budget-refused block
keeps its as-written view. Known zero/empty expansions contribute no block.
Local-data evaluation has a separate 5,000-extra-conversion budget per directory
pass and retains truncated collection shapes up to 512 entries, filling omitted
entries with unknown values. Larger or unresolved shapes remain unknown rather
than pretending a short collection is complete.

Dynamic blocks evaluate within each instance, with the existing per-block and
per-resource limits. JSON supports object and array forms of dynamic block
declarations and dynamic blocks nested in generated content. The plain parser keeps unresolved,
over-limit, or labeled JSON dynamic declarations as written. Module
evaluation uses its existing evaluator and budgets; successfully instantiated
resources/data suppress their defining-file copies in every plain-parser layer.
Truncated module resources receive one as-written tail view evaluated with the
caller's inputs before defining-file copies are suppressed, avoiding duplicate
concrete findings and false positives from module defaults. These scan views do
not change evaluated instance collections or instantiation-budget decisions.
Unresolved module calls retain defining-file copies. Module instance layers also
retain evaluated peer resources/data as shared context. Repeated context findings
are removed while actual module instances keep their existing multiplicity.

Finding/report identity is unchanged. Plain-parser instances with identical
findings are reported once, while existing module evaluation can report multiple
instances at the same definition. Distinct evidence is preserved, but reports
still identify the declaration: separate instance addresses, tags, and
fingerprints are deferred to concern 6 of the split of PR #413. Rule-dependency
layer filtering, line-info reparse caching, and specialized comparison
optimizations are outside this change.
