<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;

/**
 * The content of an artifact-signature bundle: the digest of the signed artifact
 * and the raw signature over it (as produced by `cosign sign-blob`).
 */
final class MessageSignature
{
    /**
     * @param string $digest    raw digest bytes of the artifact
     * @param string $signature raw signature bytes over the artifact
     */
    public function __construct(
        public readonly HashAlgorithm $algorithm,
        public readonly string $digest,
        public readonly string $signature,
    ) {
        if (strlen($digest) !== $algorithm->digestLength()) {
            throw new InvalidBundleInputException(sprintf(
                'A %s digest must be %d bytes, got %d.',
                $algorithm->value,
                $algorithm->digestLength(),
                strlen($digest),
            ));
        }

        if ($signature === '') {
            throw new InvalidBundleInputException('Message signature must not be empty.');
        }
    }

    /** @return array{messageDigest: array{algorithm: string, digest: string}, signature: string} */
    public function toArray(): array
    {
        return [
            'messageDigest' => [
                'algorithm' => $this->algorithm->value,
                'digest' => base64_encode($this->digest),
            ],
            'signature' => base64_encode($this->signature),
        ];
    }
}
