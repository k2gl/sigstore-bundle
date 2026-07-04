<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle;

use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;

/**
 * A Rekor transparency-log entry as carried in a bundle: where the entry lives
 * (log id and index), what kind it is, when it was integrated, and the proofs
 * that it is really in the log — an inclusion promise (signed entry timestamp),
 * an inclusion proof, or both.
 *
 * The values come from Rekor when the entry is created; this type just holds
 * them so the builder can place them in the bundle. At least one of the two
 * proofs must be present, and a v0.2+ bundle needs the inclusion proof.
 */
final class TransparencyLogEntry
{
    /**
     * @param int          $logIndex             the entry's index in the log
     * @param string       $logId                raw log id (key id) bytes
     * @param string       $kind                 Rekor entry kind, e.g. "hashedrekord" or "dsse"
     * @param string       $version              entry kind version, e.g. "0.0.1"
     * @param string       $canonicalizedBody    raw canonical Rekor entry body bytes
     * @param ?int         $integratedTime       Unix seconds the entry was integrated (Rekor v1; absent for v2)
     * @param ?string      $inclusionPromise      raw signed-entry-timestamp bytes, or null
     * @param ?InclusionProof $inclusionProof
     */
    public function __construct(
        public readonly int $logIndex,
        public readonly string $logId,
        public readonly string $kind,
        public readonly string $version,
        public readonly string $canonicalizedBody,
        public readonly ?int $integratedTime = null,
        public readonly ?string $inclusionPromise = null,
        public readonly ?InclusionProof $inclusionProof = null,
    ) {
        if ($logIndex < 0) {
            throw new InvalidBundleInputException('Transparency-log index must not be negative.');
        }

        if ($kind === '' || $version === '') {
            throw new InvalidBundleInputException('Transparency-log entry needs a kind and version.');
        }

        if ($canonicalizedBody === '') {
            throw new InvalidBundleInputException('Transparency-log entry needs a canonicalized body.');
        }

        if ($inclusionPromise === null && $inclusionProof === null) {
            throw new InvalidBundleInputException(
                'Transparency-log entry needs an inclusion promise, an inclusion proof, or both.'
            );
        }
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $entry = [
            'logIndex' => (string) $this->logIndex,
            'logId' => ['keyId' => base64_encode($this->logId)],
            'kindVersion' => ['kind' => $this->kind, 'version' => $this->version],
        ];

        if ($this->integratedTime !== null) {
            $entry['integratedTime'] = (string) $this->integratedTime;
        }

        if ($this->inclusionPromise !== null) {
            $entry['inclusionPromise'] = ['signedEntryTimestamp' => base64_encode($this->inclusionPromise)];
        }

        if ($this->inclusionProof !== null) {
            $entry['inclusionProof'] = $this->inclusionProof->toArray();
        }
        $entry['canonicalizedBody'] = base64_encode($this->canonicalizedBody);

        return $entry;
    }
}
