<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

use JsonException;
use K2gl\Dsse\Envelope;
use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;

/**
 * A Sigstore bundle (the `.sigstore.json` that cosign, gitsign and npm/PyPI
 * provenance emit): a signing identity, one or more transparency-log entries,
 * optional RFC 3161 timestamps, and exactly one content — a DSSE envelope (an
 * attestation) or a message signature (an artifact signature).
 *
 * This is the emit side of the format: hand it the components (a signature or
 * envelope you produced, the Fulcio certificate, the Rekor entry) and it lays
 * them out as the canonical v0.3 JSON. It does no signing and no I/O.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
 */
final class Bundle
{
    public const MEDIA_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json';

    /**
     * @param list<TransparencyLogEntry> $tlogEntries
     * @param list<string>               $rfc3161Timestamps raw DER RFC 3161 timestamp tokens
     */
    private function __construct(
        public readonly SigningIdentity $identity,
        public readonly array $tlogEntries,
        public readonly array $rfc3161Timestamps,
        public readonly ?Envelope $dsseEnvelope,
        public readonly ?MessageSignature $messageSignature,
    ) {}

    /**
     * A DSSE-attestation bundle (the content cosign/gitsign attestations carry).
     *
     * @param list<TransparencyLogEntry> $tlogEntries
     * @param list<string>               $rfc3161Timestamps
     */
    public static function forDsse(
        Envelope $envelope,
        SigningIdentity $identity,
        array $tlogEntries,
        array $rfc3161Timestamps = [],
    ): self {
        return new self(
            identity: $identity,
            tlogEntries: self::requireTlog($tlogEntries),
            rfc3161Timestamps: $rfc3161Timestamps,
            dsseEnvelope: $envelope,
            messageSignature: null,
        );
    }

    /**
     * An artifact-signature bundle (the content `cosign sign-blob` produces).
     *
     * @param list<TransparencyLogEntry> $tlogEntries
     * @param list<string>               $rfc3161Timestamps
     */
    public static function forMessageSignature(
        MessageSignature $messageSignature,
        SigningIdentity $identity,
        array $tlogEntries,
        array $rfc3161Timestamps = [],
    ): self {
        return new self(
            identity: $identity,
            tlogEntries: self::requireTlog($tlogEntries),
            rfc3161Timestamps: $rfc3161Timestamps,
            dsseEnvelope: null,
            messageSignature: $messageSignature,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $bundle = [
            'mediaType' => self::MEDIA_TYPE,
            'verificationMaterial' => $this->verificationMaterial(),
        ];

        if ($this->dsseEnvelope !== null) {
            $bundle['dsseEnvelope'] = $this->dsseEnvelope->toArray();
        } else {
            $bundle['messageSignature'] = $this->messageSignature?->toArray();
        }

        return $bundle;
    }

    public function toJson(): string
    {
        try {
            return json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new InvalidBundleInputException('Bundle could not be encoded as JSON: ' . $e->getMessage(), previous: $e);
        }
    }

    /** @return array<string, mixed> */
    private function verificationMaterial(): array
    {
        $material = $this->identity->toArray();
        $material['tlogEntries'] = array_map(
            static fn (TransparencyLogEntry $entry): array => $entry->toArray(),
            $this->tlogEntries,
        );

        if ($this->rfc3161Timestamps !== []) {
            $material['timestampVerificationData'] = [
                'rfc3161Timestamps' => array_map(
                    static fn (string $token): array => ['signedTimestamp' => base64_encode($token)],
                    $this->rfc3161Timestamps,
                ),
            ];
        }

        return $material;
    }

    /**
     * @param  list<TransparencyLogEntry> $tlogEntries
     * @return list<TransparencyLogEntry>
     */
    private static function requireTlog(array $tlogEntries): array
    {
        if ($tlogEntries === []) {
            throw new InvalidBundleInputException('A bundle needs at least one transparency-log entry.');
        }

        return $tlogEntries;
    }
}
