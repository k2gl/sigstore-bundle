# Build Sigstore bundles in PHP

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/sigstore-bundle/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/sigstore-bundle/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/sigstore-bundle?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/sigstore-bundle)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/sigstore-bundle?color=yellowgreen)](https://packagist.org/packages/k2gl/sigstore-bundle)

Assemble a Sigstore bundle — the `.sigstore.json` that cosign, gitsign and npm/PyPI
provenance emit — from PHP. This is the counterpart to verification: hand it the
pieces you already have (a signature or DSSE envelope, the Fulcio certificate, the
Rekor entry) and it lays them out as the canonical **v0.3** JSON that verifiers accept.

It does no signing and no network I/O — it is the format layer. The signature, the
certificate and the transparency-log entry come from elsewhere (your signer, Fulcio,
Rekor); this package places them in a well-formed bundle.

## Requirements

- PHP 8.1+
- [`k2gl/dsse`](https://github.com/k2gl/dsse) (for the DSSE envelope content)

## Installation

```bash
composer require k2gl/sigstore-bundle
```

## Usage

### A DSSE-attestation bundle

```php
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\InclusionProof;
use K2gl\SigstoreBundle\TransparencyLogEntry;

$rekorEntry = new TransparencyLogEntry(
    logIndex: 148_384_212,
    logId: $logKeyIdBytes,
    kind: 'dsse',
    version: '0.0.2',
    canonicalizedBody: $canonicalBodyBytes,
    inclusionProof: new InclusionProof(
        logIndex: 148_384_212,
        rootHash: $rootHashBytes,
        treeSize: 148_384_213,
        hashes: $siblingHashBytes,       // list of raw hashes, bottom to top
        checkpoint: $signedCheckpoint,   // the signed note string
    ),
);

$json = BundleBuilder::forDsse($envelope)   // a K2gl\Dsse\Envelope you signed
    ->withCertificate($fulcioLeafDer)       // raw DER of the Fulcio leaf
    ->addTransparencyLogEntry($rekorEntry)
    ->toJson();

file_put_contents('artifact.sigstore.json', $json);
```

### An artifact-signature bundle

```php
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\MessageSignature;

$signature = new MessageSignature(
    algorithm: HashAlgorithm::SHA2_256,
    digest: $artifactSha256,   // raw 32-byte digest
    signature: $rawSignature,  // raw signature over the artifact
);

$json = BundleBuilder::forMessageSignature($signature)
    ->withCertificate($fulcioLeafDer)
    ->addTransparencyLogEntry($rekorEntry)
    ->addRfc3161Timestamp($rfc3161TokenDer) // optional trusted timestamp
    ->toJson();
```

### Signing identity

Pick one, matching how the artifact was signed:

- `->withCertificate($der)` — a single Fulcio leaf certificate (the keyless default).
- `->withCertificateChain([$leaf, $intermediate, $root])` — a full X.509 chain.
- `->withPublicKey($hint)` — a key-based identity; the bundle only names the key by hint.

## Compatibility

The output is byte-for-byte the same structure the reference tooling emits: the test
suite rebuilds real cosign/GitHub v0.3 bundles (DSSE, message signature, and with an
RFC 3161 timestamp) from their components and checks the result is identical. Bundles
built here verify with [`k2gl/sigstore-verify`](https://github.com/k2gl/sigstore-verify)
and with `cosign`.

## Pull requests are always welcome
[Collaborate with pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)
