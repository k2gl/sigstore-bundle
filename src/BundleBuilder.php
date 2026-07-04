<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

use K2gl\Dsse\Envelope;
use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;

/**
 * A fluent way to assemble a {@see Bundle}: pick the content (a DSSE envelope or
 * a message signature), set the signing identity, and add the Rekor entries and
 * any RFC 3161 timestamps, then call {@see toJson()}.
 *
 * ```php
 * $json = BundleBuilder::forDsse($envelope)
 *     ->withCertificate($fulcioLeafDer)
 *     ->addTransparencyLogEntry($rekorEntry)
 *     ->toJson();
 * ```
 */
final class BundleBuilder
{
    private ?SigningIdentity $identity = null;

    /** @var list<TransparencyLogEntry> */
    private array $tlogEntries = [];

    /** @var list<string> */
    private array $rfc3161Timestamps = [];

    private function __construct(
        private readonly ?Envelope $dsseEnvelope,
        private readonly ?MessageSignature $messageSignature,
    ) {}

    public static function forDsse(Envelope $envelope): self
    {
        return new self($envelope, null);
    }

    public static function forMessageSignature(MessageSignature $messageSignature): self
    {
        return new self(null, $messageSignature);
    }

    /** A single Fulcio leaf certificate (raw DER) — the keyless v0.3 default. */
    public function withCertificate(string $der): self
    {
        $this->identity = SigningIdentity::certificate($der);

        return $this;
    }

    /**
     * A full X.509 chain, leaf first (raw DER each).
     *
     * @param list<string> $ders
     */
    public function withCertificateChain(array $ders): self
    {
        $this->identity = SigningIdentity::certificateChain($ders);

        return $this;
    }

    /** A public-key identity: the bundle names the key by hint only. */
    public function withPublicKey(string $hint): self
    {
        $this->identity = SigningIdentity::publicKey($hint);

        return $this;
    }

    public function addTransparencyLogEntry(TransparencyLogEntry $entry): self
    {
        $this->tlogEntries[] = $entry;

        return $this;
    }

    /** @param string $token raw DER RFC 3161 timestamp token */
    public function addRfc3161Timestamp(string $token): self
    {
        if ($token === '') {
            throw new InvalidBundleInputException('RFC 3161 timestamp token must not be empty.');
        }
        $this->rfc3161Timestamps[] = $token;

        return $this;
    }

    public function build(): Bundle
    {
        $identity = $this->identity
            ?? throw new InvalidBundleInputException('A bundle needs a signing identity; call withCertificate(), withCertificateChain() or withPublicKey().');

        if ($this->dsseEnvelope !== null) {
            return Bundle::forDsse($this->dsseEnvelope, $identity, $this->tlogEntries, $this->rfc3161Timestamps);
        }

        // The constructor guarantees exactly one content is set.
        return Bundle::forMessageSignature($this->messageSignature ?? throw new InvalidBundleInputException('Bundle has no content.'), $identity, $this->tlogEntries, $this->rfc3161Timestamps);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->build()->toArray();
    }

    public function toJson(): string
    {
        return $this->build()->toJson();
    }
}
