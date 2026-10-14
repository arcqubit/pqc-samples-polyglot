# CryptoScan local builds

CryptoScan version `1.4.0-local`, built with Go 1.26.5 for 64-bit x86 (amd64),
with CGO disabled. This is the previous scanner build. The pipeline now uses
[`aqb-openscan-cli`](../aqb-openscan-cli/README.md).

Windows (PowerShell, from the repository root):

```powershell
.\tools\cryptoscan\cryptoscan-windows-amd64.exe version
.\tools\cryptoscan\cryptoscan-windows-amd64.exe scan . `
  --exclude 'tools/*,.github/*,.cryptoscan-baseline/*' `
  --format json --pretty --no-color --output polyglot-findings.json
```

Linux (from the repository root):

```sh
chmod +x tools/cryptoscan/cryptoscan-linux-amd64
./tools/cryptoscan/cryptoscan-linux-amd64 version
./tools/cryptoscan/cryptoscan-linux-amd64 scan . \
  --exclude 'tools/*,.github/*,.cryptoscan-baseline/*' \
  --format json --pretty --no-color --output polyglot-findings.json
```

The scanner exits with status 1 when critical findings are present by default,
even when it successfully writes the report. The sample pipeline validates the
report and accepts that finding status; other execution errors fail the job.
Use `scan --help` for suppression, filtering, and severity options.

Only the Linux binary, `checksums-linux.txt`, this README, and the license are
included in Git. Windows builds, combined local checksums, and generated reports
are ignored. To update the Linux binary, also regenerate its checksum from this
directory with `sha256sum cryptoscan-linux-amd64 > checksums-linux.txt`.

This build's CLI documents known limitations: DSA key generation and compound
identifiers such as `RSAPrivateKey` are not detected. Git-history scanning,
configurable context depth, maximum depth, and non-file grouping flags are not
implemented. Results are pattern matches that require source review.

The included `LICENSE` applies to CryptoScan. Full documentation is available
at https://github.com/csnp/cryptoscan.
