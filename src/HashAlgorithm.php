<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

/**
 * The message-digest algorithms a Sigstore bundle can name, with the exact
 * spelling the protobuf JSON mapping uses on the wire (e.g. "SHA2_256").
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto
 */
enum HashAlgorithm: string
{
    case SHA2_256 = 'SHA2_256';
    case SHA2_384 = 'SHA2_384';
    case SHA2_512 = 'SHA2_512';

    /** The number of bytes a digest for this algorithm must have. */
    public function digestLength(): int
    {
        return match ($this) {
            self::SHA2_256 => 32,
            self::SHA2_384 => 48,
            self::SHA2_512 => 64,
        };
    }
}
