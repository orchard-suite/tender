# Install Tender for this user on Windows.
#
#   irm https://raw.githubusercontent.com/orchard-suite/tender/main/install.ps1 | iex
#
# It downloads the release for this machine, checks it against SHA256SUMS,
# and, when cosign is installed, checks SHA256SUMS against the release's
# keyless signature. It installs %LOCALAPPDATA%\Programs\tender\tender.exe
# and puts that folder on this user's PATH. It does not start anything: run
# `tender install` for the scheduled task, after tender.yaml is in place.
# $env:VERSION picks a release.
$ErrorActionPreference = 'Stop'
$repo = 'orchard-suite/tender'
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$name = "tender-windows-$arch.exe"
$base = if ($env:VERSION) { "https://github.com/$repo/releases/download/v$($env:VERSION.TrimStart('v'))" } else { "https://github.com/$repo/releases/latest/download" }

$dir = Join-Path ([IO.Path]::GetTempPath()) ("tender-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  foreach ($f in @($name, 'SHA256SUMS', 'SHA256SUMS.sigstore.json')) {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$f" -OutFile (Join-Path $dir $f)
  }
  if (Get-Command cosign -ErrorAction SilentlyContinue) {
    & cosign verify-blob --bundle (Join-Path $dir 'SHA256SUMS.sigstore.json') `
      --certificate-oidc-issuer https://token.actions.githubusercontent.com `
      --certificate-identity-regexp "^https://github.com/$repo/" (Join-Path $dir 'SHA256SUMS') *> $null
    if ($LASTEXITCODE -ne 0) { throw "SHA256SUMS is not signed by $repo's release workflow" }
    Write-Host 'Signature checked.'
  } else {
    Write-Host 'cosign is not installed: checking the download against SHA256SUMS only.'
  }
  $line = Get-Content (Join-Path $dir 'SHA256SUMS') | Where-Object { $_ -match " $([regex]::Escape($name))$" }
  if (-not $line) { throw "SHA256SUMS does not list $name" }
  $want = ($line -split ' ')[0]
  $have = (Get-FileHash -Algorithm SHA256 (Join-Path $dir $name)).Hash.ToLower()
  if ($want -ne $have) { throw "$name does not match SHA256SUMS" }

  $target = Join-Path $env:LOCALAPPDATA 'Programs\tender'
  New-Item -ItemType Directory -Force -Path $target | Out-Null
  Copy-Item -Force (Join-Path $dir $name) (Join-Path $target 'tender.exe')
  $path = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($path -split ';') -notcontains $target) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$target".TrimStart(';'), 'User')
    Write-Host "Added $target to PATH; open a new terminal."
  }
  Write-Host "Installed $(& (Join-Path $target 'tender.exe') version) to $target"
  Write-Host 'Next: put tender.yaml in place (tender help shows where), then run: tender install'
} finally {
  Remove-Item -Recurse -Force $dir
}
