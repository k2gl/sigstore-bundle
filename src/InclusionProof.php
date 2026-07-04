<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;

/**
 * A Merkle inclusion proof for a transparency-log entry: the entry's position
 * and the sibling hashes that reproduce the log's root at a signed checkpoint.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1
 */
final class InclusionProof
{
    /**
     * @param int          $logIndex  the entry's index in the log
     * @param string       $rootHash  raw Merkle root hash bytes
     * @param int          $treeSize  the log size the proof is against
     * @param list<string> $hashes    raw sibling hash bytes, bottom to top
     * @param string       $checkpoint the signed note (checkpoint) the root came from
     */
    public function __construct(
        public readonly int $logIndex,
        public readonly string $rootHash,
        public readonly int $treeSize,
        public readonly array $hashes,
        public readonly string $checkpoint,
    ) {
        if ($logIndex < 0) {
            throw new InvalidBundleInputException('Inclusion-proof log index must not be negative.');
        }

        if ($treeSize <= $logIndex) {
            throw new InvalidBundleInputException('Inclusion-proof tree size must be greater than the log index.');
        }

        if ($checkpoint === '') {
            throw new InvalidBundleInputException('Inclusion proof must carry a checkpoint.');
        }
    }

    /**
     * @return array{
     *     logIndex: string,
     *     rootHash: string,
     *     treeSize: string,
     *     hashes: list<string>,
     *     checkpoint: array{envelope: string}
     * }
     */
    public function toArray(): array
    {
        return [
            'logIndex' => (string) $this->logIndex,
            'rootHash' => base64_encode($this->rootHash),
            'treeSize' => (string) $this->treeSize,
            'hashes' => array_map(static fn (string $hash): string => base64_encode($hash), $this->hashes),
            'checkpoint' => ['envelope' => $this->checkpoint],
        ];
    }
}
