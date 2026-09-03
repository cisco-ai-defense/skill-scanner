# Skill Scanner cel-go helper

This directory builds the production CEL decision runtime. It uses the
official `cel.dev/cel-go` module at exactly `v0.32.0` (upstream
`github.com/google/cel-go`, tag commit
`f2039bc647bca407d882d90436fc8b91bab1ae62`). Skill Scanner qualifies the
helper with Go `1.27.1` or newer; release builds use `-trimpath` and
`-buildvcs=false`.

The helper is a persistent local process. Python sends one bounded JSON frame
containing the typed `ScanFacts` descriptor and the complete CEL generation,
then reuses the process for bounded protobuf evaluation frames. It does not
spawn per finding. A generation becomes active only after every expression
compiles and returns `bool`. Evaluations have protobuf-size, wall-clock, and
cel-go cost limits. Protocol, timeout, cost, panic, and type failures return a
stable error code so the Python gate retains the original finding.

The compile environment uses an explicit standard-library allowlist. Rules may
only read the typed `f` root, select protobuf fields, combine Boolean and
comparison expressions, use list membership and `has`/`exists`/`all`, and call
`startsWith`/`endsWith`/`contains`/`matches` with literal strings. A second
checked-AST pass rejects construction, indexing, arithmetic, dynamic values,
other functions or macros, excessive nesting, and oversized literal regexes.
Wire JSON rejects unknown or duplicate fields.

Build and test the host binary:

```sh
go test ./...
go build -trimpath -buildvcs=false -o skill-scanner-cel-go .
./skill-scanner-cel-go --version
```

The release builder produces pure-Go binaries for glibc Linux amd64/arm64,
macOS 13+ amd64/arm64, and Windows amd64. Go 1.27.1 or newer is required to
build the helper; older Go linkers emit an incompatible Darwin deployment
floor. Platform wheels explicitly support
CPython 3.11-3.14, contain exactly one matching binary plus its hash-bound
hash/target manifest in `skill_scanner/core/cel/_bin/`, and are natively
smoke-tested. Release assets export every Go module checksum and helper digest
and merge both into the CycloneDX SBOM. Administrators may explicitly override
the packaged path with `SKILL_SCANNER_CEL_GO_HELPER` for a trusted local build.
