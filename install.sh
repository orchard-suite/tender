#!/bin/sh
# Install Tender for this user on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/orchard-suite/tender/main/install.sh | sh
#
# It downloads the release for this machine, checks it against SHA256SUMS,
# and, when cosign is installed, checks SHA256SUMS against the release's
# keyless signature. It installs ~/.local/bin/tender. It does not start
# anything: run `tender install` for the service, after tender.yaml is in
# place. VERSION=0.1.0 picks a release; INSTALL_DIR picks the folder.
set -eu

REPO="orchard-suite/tender"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

fail() { echo "tender install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unsupported operating system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

if [ -n "${VERSION:-}" ]; then
  base="https://github.com/$REPO/releases/download/v${VERSION#v}"
else
  base="https://github.com/$REPO/releases/latest/download"
fi

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
name="tender-$os-$arch"
for f in "$name" SHA256SUMS SHA256SUMS.sigstore.json; do
  curl -fsSL -o "$dir/$f" "$base/$f" || fail "could not download $f from $base"
done

if command -v cosign >/dev/null 2>&1; then
  cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp "^https://github.com/$REPO/" \
    "$dir/SHA256SUMS" >/dev/null 2>&1 || fail "SHA256SUMS is not signed by $REPO's release workflow"
  echo "Signature checked."
else
  echo "cosign is not installed: checking the download against SHA256SUMS only."
fi

want=$(grep " $name\$" "$dir/SHA256SUMS" | cut -d' ' -f1)
[ -n "$want" ] || fail "SHA256SUMS does not list $name"
if command -v sha256sum >/dev/null 2>&1; then
  have=$(sha256sum "$dir/$name" | cut -d' ' -f1)
else
  have=$(shasum -a 256 "$dir/$name" | cut -d' ' -f1)
fi
[ "$want" = "$have" ] || fail "$name does not match SHA256SUMS"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$dir/$name" "$INSTALL_DIR/tender"
echo "Installed $("$INSTALL_DIR/tender" version) to $INSTALL_DIR/tender"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add $INSTALL_DIR to PATH." ;;
esac
echo "Next: put tender.yaml in place (tender help shows where), then run: tender install"
