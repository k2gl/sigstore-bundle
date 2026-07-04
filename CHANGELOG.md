# Changelog

## 1.0.0

First public release. Builds Sigstore bundles (`.sigstore.json`, media type
`application/vnd.dev.sigstore.bundle.v0.3+json`) from PHP — the emit side of the
format, the counterpart to verification.

- **`BundleBuilder`** — a fluent way to assemble a bundle from its parts: a DSSE
  envelope (`forDsse()`) or a message signature (`forMessageSignature()`), a signing
  identity (`withCertificate()` / `withCertificateChain()` / `withPublicKey()`), one
  or more Rekor entries, and optional RFC 3161 timestamps. `toJson()` / `toArray()`.
- **`Bundle`** — the immutable model, with `forDsse()` / `forMessageSignature()`
  factories and canonical v0.3 serialisation.
- **`TransparencyLogEntry`** / **`InclusionProof`** — Rekor entries carried by a
  bundle, with an inclusion promise, an inclusion proof, or both; `integratedTime` is
  optional (Rekor v1 only).
- **`MessageSignature`**, **`SigningIdentity`**, **`HashAlgorithm`** — the value types
  the bundle is built from, validated at construction (fail-closed on malformed input).
- No signing, no network I/O — the components come from your signer, Fulcio and Rekor.
- Verified against the reference format: the suite rebuilds real cosign/GitHub v0.3
  bundles from their components and checks the result is structurally identical, and
  bundles built here verify with `k2gl/sigstore-verify`.
