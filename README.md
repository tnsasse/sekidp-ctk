# sekidp-ctk

A headless conformance test kit for **sector identity providers** (*sektorale
IDPs*) of the gematik TI federation. It tests an IdP against
[gemSpec_IDP_Sek 3.3.0](gemspec/gemSpec_IDP_Sek_V3.3.0.pdf). Section
references are requirement IDs, e.g. `gemSpec_IDP_Sek A_22993`.

The kit acts as a Fachdienst of the federation: it authenticates with mTLS
(`self_signed_tls_client_auth`), uses PAR and PKCE, and decrypts the ID token.
It logs in by filling in the IdP's HTML forms with a plain HTTP client, so no
human and no browser are needed and it runs in CI.

## Quick start

```sh
make build
CTK_TEST_USER=... CTK_TEST_PASSWORD=... ./sekidp-ctk run -config my-idp.yaml --full
```

Start from [`targets/idp.example.yaml`](targets/idp.example.yaml). The kit
needs a test Fachdienst registered with the environment's Federation Master:
its client_id (entity identifier), the self-signed TLS client certificate and
key from its entity statement (`self_signed_tls_client_auth`), and the private
key of its encryption key (to decrypt ID tokens).

`${VAR}` references in config values are expanded from the environment, so
secrets never need to be committed. A missing variable is an error. Relative
file paths are resolved against the config file's directory.

## Tests

| IDs | Area | Needs |
|-----|------|-------|
| `GES` | Entity statement: header (ES256, `entity-statement+jwt`, UUIDv7 kid), self-signature, iss/sub, ≤ 24h validity, daily reissue, key IDs and key age ≤ 398 days, P-256/P-384, every required `openid_provider` field and value, scopes/claims, `ti_features_supported`, reachable URLs | IdP entity ID only |
| `GFM` | Trust chain: `authority_hints`, the Federation Master's subordinate statement and the keys it vouches for; the IdP's entry in the signed IDP list | `federation_master` |
| `GTL`, `GAP` | Publicly trusted VAU certificate, dedicated non-wildcard subdomain, CT SCTs, CAA records, certificate lifetime ≤ 398 days, key strength; App Links / Universal Links files | IdP entity ID only |
| `GPR` | PAR: 201 response, `request_uri` lifetime ≤ 90s, 401 for missing/unpublished certificates and unknown clients, `redirect_uri`/scope validation, S256-only PKCE, claims parameter, error format, unguessable `request_uri` | `fachdienst` |
| `GAZ` | Authorization endpoint: PAR required, unknown/foreign `request_uri`, no code without login, code + state to the redirect URI, `prompt=login`/`max_age=0`, expired `request_uri` (slow) | `fachdienst`, `login` |
| `GTK` | Token endpoint and ID token: JWE (ECDH-ES/A256GCM, kid, `version` header), ES256 signature with x5c by a published key, ≤ 300s lifetime, iss/aud/nonce, acr/amr coding, claim formats, no unrequested claims, pairwise sub, single-use codes, PKCE verification, mTLS, code expiry ≤ 90s (slow) | `fachdienst` (+ `enc_key`), `login`, optionally `fachdienst_b` |

Version 3.3.0 dropped the detailed flow tables (PAR parameters, ID token
header/signature/body claims, key sets, IDP list) that the requirements and
gemSpec_IDP_FD still reference. The kit takes them from
[gemSpec_IDP_Sek 3.2.0 §7.1.4](gemspec/gemSpec_IDP_Sek_V3.2.0.html): where a
table fixes values exactly, the check is a MUST; where it only gives an
example, a SHOULD. Assertions based on them say "gemSpec_IDP_Sek 3.2.0
Table N".

The kit also follows the Fachdienst rules of
[gemSpec_IDP_FD 2.2.0](gemspec/gemSpec_IDP_FD_V2.2.0.html), since it plays
the Fachdienst: nonce and code_verifier of 43–128 characters (A_24833-01),
`acr_values` in every pushed request (A_23004-01), a repeated PAR when the
first one is answered with 401 during automatic registration (A_23500), and
EC P-256 keys only (A_23196, checked when the config is loaded). GFM-04
checks the Federation Master's signed IDP list (AF_10116).

Organisational requirements (VAU operation, HSM, logging, georedundancy) and
requirements on the Authenticator app cannot be tested over the network and
are not covered.

The suite is validated by unit tests against an in-process fake sector IdP
and Federation Master (`internal/gematik/fake_test.go`). One test proves the
compliant fake passes everything; another injects individual violations and
checks that the corresponding tests fail.

## CLI

```
sekidp-ctk list                        # test catalog
sekidp-ctk run -config FILE [flags]
  -format text|json|junit|html  report format for stdout / -o (default text)
  -o FILE                   write the report to FILE
  -junit FILE, -json FILE   additionally write those formats
  -html FILE                additionally write a self-contained HTML report
                            (automatic with -full: <target-name>-report.html; -html none disables)
  -strict                   SHOULD-level warnings fail the run
  -slow                     include slow tests (request_uri and code expiry)
  -full                     run everything: every opt-in test (implies -slow),
                            and a missing fixture is an ERROR instead of a skip
  -spec gemSpec_IDP_Sek,... only run tests of these specs (default: all)
  -run REGEX / -skip REGEX  select tests by ID, e.g. -run '^(GPR|GTK)-'
  -v 0|1|2                  0 results, summary and findings (default with -full),
                            1 (default) + logs and redacted HTTP exchanges for findings,
                            2 + every assertion of every test
```

Exit status: `0` conformant, `1` failures or errors (or warnings with
`-strict`), `2` usage or config error.

Each run ends with a summary table per spec and **findings**: every failed,
errored and warned test with what the specification expects and what the IdP
did. The HTML report holds the same information as one self-contained page
with collapsible HTTP evidence. Recorded exchanges have passwords, client
secrets, cookies and Authorization headers redacted, but tokens in response
bodies are not, so treat the report like a log file.

| Status  | Meaning |
|---------|---------|
| `PASS`  | all assertions held |
| `WARN`  | only SHOULD-level assertions failed |
| `FAIL`  | at least one MUST-level assertion failed |
| `SKIP`  | not applicable to this configuration (missing fixture) |
| `ERROR` | a precondition could not be established, e.g. no code was issued |

## Layout

```
cmd/sekidp-ctk       entry point
internal/gematik     gemSpec_IDP_Sek catalog, config, login methods, fake IdP for tests
internal/cli         CLI (run/list, flags, reports)
internal/suite       assertion framework, runner, redacting HTTP recorder
internal/useragent   headless user agent (form-driving login)
internal/oauth       token/PAR endpoint client
internal/yamlenv     YAML decoding with ${VAR} expansion
internal/report      text / JSON / JUnit / HTML
gemspec/             gemSpec_IDP_Sek 3.2.0 and 3.3.0, gemSpec_IDP_FD 2.2.0
targets/             example target config
```
