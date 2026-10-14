module github.com/corazawaf/coraza-proxy-wasm

// Bumped 1.23.8 -> 1.25.0 with the TinyGo 0.34 -> 0.39 migration. TinyGo 0.34
// capped the host Go at 1.23, pinning the plugin to an EOL stdlib; 0.39 raises
// the ceiling so CVE-driven bumps (e.g. golang.org/x/net) are unblocked.
go 1.25.0

require (
	github.com/corazawaf/coraza-wasilibs v0.2.0
	github.com/corazawaf/coraza/v3 v3.8.1
	github.com/stretchr/testify v1.11.1
	github.com/tetratelabs/proxy-wasm-go-sdk v0.24.0
	github.com/tidwall/gjson v1.18.0
)

// The wasilibs operator backends are re-pointed at local forks so @rx/@pm/@detectXSS
// keep their C-wasm speed under TinyGo 0.39, whose newer wasi-libc the frozen 0.34-era
// archives no longer link against. coraza-wasilibs still drives registration; only the
// compiled archives change. See each fork's TIGERA-FORK.md.
//   - go-re2: libcre2.a is rebuilt from the Rust `regex` crate behind a cre2-shaped C ABI
//     (buildtools/cre2). Non-recursive, so it kills the stdlib-regexp compile stack-overflow
//     that blocks a pure-Go @rx at CRS scale. The aho-corasick C ABI backing @pm is folded
//     INTO this one archive -- two Rust staticlibs clash on std panic symbols and TinyGo
//     0.39's wasm-ld has no --allow-multiple-definition.
//   - go-libinjection: libinjection.a rebuilt for wasm32-wasip1 with wasi-sdk-24.
replace github.com/wasilibs/go-re2 => ./third_party/go-re2

replace github.com/wasilibs/go-aho-corasick => ./third_party/go-aho-corasick

replace github.com/wasilibs/go-libinjection => ./third_party/go-libinjection

require (
	github.com/corazawaf/libinjection-go v0.3.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976 // indirect
	github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092 // indirect
	github.com/kaptinlin/go-i18n v0.1.4 // indirect
	github.com/kaptinlin/jsonschema v0.4.6 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/magefile/mage v1.17.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/tetratelabs/wazero v1.7.3 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	github.com/wasilibs/go-aho-corasick v0.6.0 // indirect
	github.com/wasilibs/go-libinjection v0.5.0 // indirect
	github.com/wasilibs/go-re2 v1.6.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)
