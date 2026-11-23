# Tender

Tender is the device agent of the Orchard suite. It runs on a person's
machine, as that person, and reports what only the machine can see to the
members an estate names. A tender is the small boat that carries things
between a ship and the shore.

Each member owns its reader, a small module in the member's own
repository. Tender compiles the readers in and owns what they share: the
identity, the schedule, the saved place, and sending again after a
failure.

This build carries one reader:

| Reader | Member | What it reports |
| --- | --- | --- |
| `muster` | Muster | Each git checkout's remote, its counts of staged, modified, untracked, and conflicted files, stashes, and worktrees, and each branch's name with how far it is ahead of or behind its upstream |

## The guarantees

- **Reports only.** Tender asks a member one question and sends one
  report. Nothing sends Tender a command or a query, and it never writes
  to a catalog.
- **Names and counts.** Tender refuses to send a report whose JSON holds
  a string longer than 512 bytes, and logs which reader it refused. A
  reader never sends a file's name or contents, a path above a folder, a
  commit message, or a secret.
- **Off until given an address.** A reader with no address in
  `tender.yaml` reads nothing and sends nothing.
- **It asks before it sends.** A member that says no, or takes a report
  version this build cannot write, hears nothing until it is asked again.
- **The key stays put.** Tender signs with the key in the operating
  system's store and never copies it out. Where there is no store, it
  uses a key file only its user can read.
- **No self-update.** Whatever installed Tender installs its next release.

## How a request is proven

Every request carries one header:

```
Authorization: Device <compact JWS>
```

The JWS is signed with the device's key (`ES256`, or `PS256` for an RSA
key), has `typ` `tender+jwt`, and carries the certificate chain in `x5c`,
the device certificate first, never the root. Its claims bind it to one
request and a life of five minutes:

| Claim | Meaning |
| --- | --- |
| `aud` | the member's origin, such as `https://muster.example.com` |
| `htm`, `htu` | the method, and the URL without its query |
| `bh` | base64url SHA-256 of the body |
| `iat`, `exp` | issued now, expires within 300 seconds |
| `jti` | 16 random bytes, so a member refuses a replay |

It is not a TLS client certificate, so it passes every front door and
proxy an estate runs. The member's door checks it; for a Go member, that
is `github.com/orchard-suite/platformkit/v3/device`.

## The two calls

A member that takes a reader serves both under
`/tender/v1/readers/<reader>`.

- **Ask.** `GET` answers `{"accept": true, "version": 1, "every": "15m"}`
  or `{"accept": false, "retry": "6h"}`.
- **Post.** `POST` sends
  `{"reader": "muster", "version": 1, "at": "...", "report": {...}}`.
  `204` takes it. `409` with `{"version": N}` makes Tender ask again. A
  5xx or a network failure keeps the report and sends it again with
  backoff, from 30 seconds doubling to 30 minutes; a newer report replaces
  one that waits.

## Configure

`tender.yaml` lives in the user's config folder:

| OS | Config | State and logs |
| --- | --- | --- |
| macOS | `~/Library/Application Support/tender/` | the same; logs in `~/Library/Logs/tender/` |
| Linux | `$XDG_CONFIG_HOME/tender/` | `$XDG_STATE_HOME/tender/` |
| Windows | `%APPDATA%\tender\` | `%LOCALAPPDATA%\tender\` |

`TENDER_CONFIG` names another file.

```yaml
identity:
  issuer: "CN=Example Devices Issuing CA"   # pick the store identity this issuer signed
  # or, where the OS has no store: key: <path>, cert: <path>
readers:
  muster:
    address: https://muster.example.com      # no address: the reader is off
    settings: { roots: ["~/source"], ignore: ["node_modules"] }
```

- `identity.issuer` is a distinguished name. Every attribute it names
  must be in the certificate's issuer; order and case do not matter.
  Tender picks the newest certificate from that issuer that is valid now
  and is for client authentication.
- On macOS Tender looks in the person's keychain search list; the key may
  be in the keychain or the Secure Enclave. On Windows it looks in
  `CurrentUser\My`; the key may be in the TPM or the software store. On
  Linux, and wherever `key` and `cert` are set, it reads a PEM key file,
  which must be readable by its user alone, and a PEM cert file that may
  hold the intermediates after the device certificate. With neither set
  on Linux, it reads `device.key` and `device.crt` in its state folder.
- A changed `tender.yaml` takes effect within five minutes.

## Install

macOS and Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/orchard-suite/tender/main/install.sh | sh
tender install     # a LaunchAgent on macOS, a systemd user unit on Linux
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/orchard-suite/tender/main/install.ps1 | iex
tender install     # a scheduled task at this user's logon
```

The scripts check the download against `SHA256SUMS`, and `SHA256SUMS`
against the release workflow's keyless signature when `cosign` is
installed. Each release is also one signed OCI artifact,
`ghcr.io/orchard-suite/tender:cli-<version>`, for an estate's forge to
verify and serve.

`tender uninstall` removes the service.

## Enroll, for an estate without device management

An estate whose device management issues certificates needs nothing more:
Tender finds the certificate by its issuer, and device management renews
it. An estate with none runs a small authority, [step-ca], with an OIDC
provisioner, and each person enrolls each machine once:

```bash
tender enroll --ca https://ca.example.com --fingerprint <root sha256>
```

Tender opens the browser for the person to sign in (the authorization code
flow with PKCE, on a loopback redirect), makes a new key in the store (the
Secure Enclave where the build may use it, else the login keychain; the
TPM where Windows has one, else the software store; a key file on Linux),
and hands the authority a signing request naming the device (CN, the host
name) and the person (one SAN email, from the sign-in, or `--email`). The
signed certificate is kept beside its key. `--fingerprint` pins the
authority's root when its TLS is under that root; leave it out when the
system trusts the authority.

`tender run` renews the certificate it enrolled when less than a third of
its life is left. `tender renew` does it now if it is due; `tender renew
--force` does it whatever is left. A certificate device management issued
is never renewed by Tender.

Renewal is a `POST` to step-ca's `/1.0/renew` with `Authorization: Bearer
<token>`, never TLS client authentication, so it works when a proxy ends
TLS in front of the authority. The token is what `step ca renew
--mtls=false` sends: a JWT signed by the current certificate's key, in
the store where it lives, with the chain (leaf first, no root) in its
`x5cInsecure` header and the claims `iss` `step-ca-client/1.0`, `sub` the
certificate's common name, `aud` the renew URL, `iat`, `nbf`, `exp` (five
minutes), and `jti`.

What an estate sets on its step-ca:

- **The provisioner allows renewal.** Leave `claims.disableRenewal` unset
  or `false` on the OIDC provisioner. To let a machine that was off past
  its certificate's end renew without enrolling again, set
  `claims.allowRenewalAfterExpiry: true`.
- **The template keeps the request's subject and the person's email, for
  client authentication.** step-ca's default OIDC template names the
  certificate after the token, not the request. Renewal also needs the
  digital signature key usage: step-ca refuses a renewal token whose
  certificate cannot sign.

  ```json
  {
    "subject": {{ toJson .Insecure.CR.Subject }},
    "sans": {{ toJson .SANs }},
    "keyUsage": ["digitalSignature"],
    "extKeyUsage": ["clientAuth"]
  }
  ```

- **`dnsNames` holds the name Tender reaches it by.** step-ca takes a
  renewal token only when its `aud`, `https://<name>/1.0/renew`, names one
  of the authority's `dnsNames`. Behind a proxy, that is the public name.
- **The proxy passes `/1.0/renew` and its `Authorization` header** on to
  step-ca unchanged.

[step-ca]: https://smallstep.com/docs/step-ca/

## Commands

| Command | What it does |
| --- | --- |
| `tender run` | Ask, read, and send for every reader, on the members' schedules, forever |
| `tender once` | Ask, read, and send for every reader now, and print what was sent: names and counts |
| `tender status` | Print the identity (issuer, subject, expiry), the readers, and how each last went |
| `tender enroll --ca <url>` | Sign in and get a device certificate from the estate's step-ca |
| `tender renew [--force]` | Renew the certificate Tender enrolled |
| `tender install`, `tender uninstall` | Add or remove this user's service |
| `tender version` | Print the version |

Logs are JSON lines in the log folder, `tender.log`, with one older file
kept as `tender.log.1`.

## Build

```bash
make          # build and install ~/.local/bin/tender
make check    # gofmt, vet for every OS, and every test
```

## License

MIT.
