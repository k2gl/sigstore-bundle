<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;

/**
 * The signing identity a bundle carries, in one of the three shapes the spec
 * allows: a single Fulcio leaf certificate (the v0.3 keyless default), a full
 * X.509 chain (older bundles), or a public-key hint (the key lives out of band,
 * the bundle only names it).
 */
final class SigningIdentity
{
    private const MODE_CERTIFICATE = 'certificate';
    private const MODE_CHAIN = 'x509CertificateChain';
    private const MODE_PUBLIC_KEY = 'publicKey';

    /**
     * @param self::MODE_* $mode
     * @param list<string> $certificates raw DER certificates (leaf first), empty for a public-key identity
     * @param ?string      $publicKeyHint hint naming the out-of-band key, or null
     */
    private function __construct(
        private readonly string $mode,
        private readonly array $certificates,
        private readonly ?string $publicKeyHint,
    ) {}

    /** A single Fulcio leaf certificate (raw DER) — the keyless v0.3 default. */
    public static function certificate(string $der): self
    {
        if ($der === '') {
            throw new InvalidBundleInputException('Certificate DER must not be empty.');
        }

        return new self(self::MODE_CERTIFICATE, [$der], null);
    }

    /**
     * A full X.509 chain, leaf first (raw DER each). The form older bundles use.
     *
     * @param list<string> $ders
     */
    public static function certificateChain(array $ders): self
    {
        if ($ders === []) {
            throw new InvalidBundleInputException('Certificate chain must have at least the leaf.');
        }

        foreach ($ders as $der) {
            if ($der === '') {
                throw new InvalidBundleInputException('Certificate DER must not be empty.');
            }
        }

        return new self(self::MODE_CHAIN, $ders, null);
    }

    /** A public-key identity: the bundle only names the key by hint. */
    public static function publicKey(string $hint): self
    {
        if ($hint === '') {
            throw new InvalidBundleInputException('Public-key hint must not be empty.');
        }

        return new self(self::MODE_PUBLIC_KEY, [], $hint);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return match ($this->mode) {
            self::MODE_CERTIFICATE => [
                'certificate' => ['rawBytes' => base64_encode($this->certificates[0])],
            ],
            self::MODE_CHAIN => [
                'x509CertificateChain' => [
                    'certificates' => array_map(
                        static fn (string $der): array => ['rawBytes' => base64_encode($der)],
                        $this->certificates,
                    ),
                ],
            ],
            self::MODE_PUBLIC_KEY => [
                'publicKey' => ['hint' => $this->publicKeyHint],
            ],
        };
    }
}
