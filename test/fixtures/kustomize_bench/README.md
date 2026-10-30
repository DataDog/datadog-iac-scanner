# Kustomize performance bench

`gen` writes the bench tree the performance tables are measured on: `BENCH_BASES`
bases (default 30) with `BENCH_DOCS` deployments each (default 20) and four
overlays per base (one with a patch, one with a generator). The tree is
generated into a scratch directory — nothing large is committed here.

    go run ./test/fixtures/kustomize_bench/gen /tmp/kbench
    cd /tmp/kbench && git init -q &&
      git remote add origin https://example.invalid/fixture.git &&
      git add -A && git -c user.email=bench@local -c user.name=bench commit -qm bench

Then compare builds with the rules pinned:

    ./bin/<build> fetch-bundle --output-dir /tmp/bundle
    /usr/bin/time -l ./bin/<build> scan [--x-kustomize] -p /tmp/kbench \
      -o /tmp/out --offline-bundle-path /tmp/bundle --metadata-path /tmp/meta.json
