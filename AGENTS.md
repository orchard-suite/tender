# AGENTS.md

Tender is the suite's device agent: it runs as a person on their machine,
asks each member it has an address for whether it takes a reader, and
posts that reader's report with a signed assertion. `README.md` says what
it does, the config, and the guarantees. It is in the shed: installed on
machines, not a member.

## Layout

| Path | Holds |
| --- | --- |
| `cmd/tender` | The program's entry point |
| `internal/cli` | The commands, the run loop, enrollment and renewal |
| `internal/agent` | The ask and post state machine: schedule, hold, backoff, replace |
| `internal/assertion` | The `Authorization: Device` JWS |
| `internal/identity` | The device's certificate and key: keychain, certificate store, or files |
| `internal/stepca` | The one certificate authority Tender knows: step-ca, with OIDC sign-in and bearer-token renewal |
| `internal/stepca/stepcatest` | A step-ca for tests that checks renewal tokens as step-ca does |
| `internal/reader` | The reader interface and the 512-byte string limit |
| `internal/readers/<name>` | One adapter per member's reader module |
| `internal/state`, `internal/config`, `internal/logfile` | The state file, `tender.yaml` and its paths, the JSON log |
| `internal/service` | The LaunchAgent, systemd user unit, and scheduled task |
| `internal/testpki` | An in-memory root, intermediate, and device certificates for tests |
| `e2e` | Tender against platformkit's real door and Muster's real reader |

## Rules

- The wire is fixed with the members that read it: the assertion's header
  and claims, the ask and post bodies, and the reader interface. Change
  them only with the door and the members.
- Tender only reports. Never add a command, a query, or a self-update.
- A reader's report goes through `reader.Encode`; nothing posts around it.
- A new member's reader is a module in that member's repository, added
  here as an adapter in `internal/readers/` and one line in
  `cli.Readers`. Take it by a released version, never a local `replace`.
- Another certificate authority is a package beside `internal/stepca`,
  named in the enrollment record's `authority`.
- No estate's names: tests and docs use `example.com`, `acme`, and "a
  user".

## Key stores

Tender takes the OS stores from smallstep's `go.step.sm/crypto/kms`: `mackms`
for the macOS keychain and Secure Enclave, `capi` for the Windows store
with CNG and the TPM's Platform Crypto Provider, and `softkms` for key
files. One maintained library covers finding a key, signing, making a
non-exportable key, and keeping a certificate beside it on every OS, and it
signs RSA-PSS as well as ECDSA. `github.com/github/smimesign/certstore`
finds identities but cannot make a key or keep a certificate, and has not
had a release in years.

The keychain cannot search by issuer, so on macOS Tender lists the
certificates with Apple's `security find-certificate -a -p` and opens the
key by its hash. `mackms` needs cgo, so macOS builds with cgo on a Mac;
Linux and Windows build with cgo off. The Secure Enclave needs a build
signed with the keychain entitlement; without it, enrollment makes the key
in the login keychain.

## Check

`make check` runs gofmt, vet for macOS, Linux, and Windows, and every
test. `TENDER_KEYCHAIN_TEST=1 go test ./internal/identity -run Keychain`
makes a key and a certificate in the login keychain, finds them by
issuer, signs, and removes both; run it after a change to the macOS store.

## Delivery

Agents push to main. Land with `make land`. Commit as
`<type>(tender): <description>`. CI tests on GitHub's hosted runners
(Linux, macOS, Windows), versions, and publishes signed binaries for
macOS, Linux, and Windows on amd64 and arm64; never version by hand.
