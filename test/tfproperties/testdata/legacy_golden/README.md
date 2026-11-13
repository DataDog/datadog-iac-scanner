# Legacy-document goldens

One normalized JSON file per generated cell of the fixture corpus, holding
the legacy documents a rule reads: keyed by the file the document was
written on, without the document id, with documents written on the same file
sorted by content.

`TestLegacyDocumentsMatchThePreviousEngine` in
`test/tfproperties/legacy_golden_test.go` rebuilds these documents from the
current engine's model and requires them to match, cell by cell. Differences
that are the rebuild working as designed are listed in the
`intendedDifferences` table (and the two content rules) in that file; an
unlisted difference fails, and so does a listed one that no longer matches,
so the table only shrinks.

## Where the goldens come from

The goldens were produced by a build of the engine before the model, at
commit `c3f122293` of `origin/main`, in a scratch worktree. To regenerate
them after a deliberate change:

1. Create a detached scratch worktree of the commit whose documents the
   goldens should hold. The path must not be under `/tmp` and must end in
   `datadog-iac-scanner` (some tests find the repository root that way):

   ```
   git worktree add --detach <somewhere>/datadog-iac-scanner <commit>
   ```

2. Copy the fixture corpus into the worktree:

   ```
   cp -r test/tfcorpus <worktree>/test/tfcorpus
   ```

3. Copy `test/tfproperties/goldengen/main.go` into the worktree as
   `test/goldengen/main.go`. On a checkout of the engine before the model,
   the documents come from the parser instead of the model, so adapt that
   one file: parse every `.tf` file of the root with
   `pkg/parser/terraform.NewDefault().Parse`, stamp `id` and `file` on each
   document the way `FileMetadatas.Combine` does, and strip the `_dd_lines`
   entries the way the runner prepares documents for rules.

4. Generate the goldens and copy them back:

   ```
   cd <worktree> && go run ./test/goldengen -out <out-dir>
   cp <out-dir>/*.json test/tfproperties/testdata/legacy_golden/
   ```

5. Remove the worktree (`git worktree remove <worktree>`).

The generator's cell selection (`corpusCells`) must match the grids the
golden test reads; if you change one, change both.
