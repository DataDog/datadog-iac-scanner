# SARIF schema fixture

`sarif-schema-2.1.0-errata01.json` is the unmodified official OASIS SARIF
2.1.0 errata01 JSON schema (JSON Schema draft-04).

- Published schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
- OASIS source mirror: https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
- SHA-256: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`

Retrieved on 2026-11-16 from the schema constant in
`github.com/owenrumney/go-sarif/v3@v3.3.2/pkg/report/v210/sarif/schema.go`
via the Go module proxy because direct upstream access was unavailable.
The extracted bytes match the independently obtained official schema checksum
above. This module is not a scanner dependency.

Tests load the checked-in bytes with the existing pinned
`github.com/xeipuuv/gojsonschema` validator. All schema references are local
fragments; neither the schema's `id` nor the report's `$schema` URL is fetched.
Keep the fixture unchanged, including its `suppression.status` property.
