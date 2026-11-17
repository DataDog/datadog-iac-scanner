# SARIF schema fixture

`sarif-schema-2.1.0-errata01.json` is the unmodified official OASIS SARIF
2.1.0 errata01 JSON schema (JSON Schema draft-04).

- Published schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
- OASIS source mirror: https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
- SHA-256: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`

Re-check the published schema's checksum with:

```sh
curl -fsSL https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json | shasum -a 256
```

The fixture is marked `-text` in `.gitattributes` to preserve its exact bytes
on checkouts with automatic line-ending conversion.

Copyright © OASIS Open 2023. All Rights Reserved.
See the specification's [Notices](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
and the [OASIS IPR Policy](https://www.oasis-open.org/policies-guidelines/ipr/)
for copyright and intellectual property notices.

Tests load the checked-in bytes with the existing pinned
`github.com/xeipuuv/gojsonschema` validator. All schema references are local
fragments; neither the schema's `id` nor the report's `$schema` URL is fetched.
Keep the fixture unchanged, including its `suppression.status` property.
