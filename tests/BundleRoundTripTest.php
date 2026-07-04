<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle\Tests;

use K2gl\Dsse\Envelope;
use K2gl\SigstoreBundle\Bundle;
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\InclusionProof;
use K2gl\SigstoreBundle\MessageSignature;
use K2gl\SigstoreBundle\SigningIdentity;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The strongest acceptance test for a builder: take a real v0.3 bundle emitted
 * by the reference tooling, pull its components apart, feed them back through
 * this package, and require the result to be byte-for-byte the same structure —
 * proving we lay the format out exactly as cosign/GitHub do.
 */
#[CoversClass(Bundle::class)]
#[CoversClass(BundleBuilder::class)]
#[CoversClass(SigningIdentity::class)]
#[CoversClass(MessageSignature::class)]
#[CoversClass(TransparencyLogEntry::class)]
#[CoversClass(InclusionProof::class)]
#[CoversClass(HashAlgorithm::class)]
final class BundleRoundTripTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function realBundles(): iterable
    {
        yield 'dsse attestation' => ['bundle-dsse-v0.3.json'];
        yield 'message signature' => ['bundle-msgsig-v0.3.json'];
        yield 'message signature with timestamp' => ['bundle-tsa-v0.3.json'];
    }

    #[DataProvider('realBundles')]
    public function testRebuildsRealBundleStructure(string $fixture): void
    {
        $original = $this->fixture($fixture);

        // Compare semantically: JSON object key order is not significant (a
        // verifier parses into a structure), so normalise object key order
        // while leaving array element order — tlog entries, proof hashes — intact.
        fact(self::normalize($this->rebuild($original)->toArray()))->is($this->normalize($original));
    }

    /**
     * @param  array<mixed> $value
     * @return array<mixed>
     */
    private static function normalize(array $value): array
    {
        if (! array_is_list($value)) {
            ksort($value);
        }

        return array_map(
            static fn (mixed $item): mixed => is_array($item) ? self::normalize($item) : $item,
            $value,
        );
    }

    #[DataProvider('realBundles')]
    public function testEmitsTheCanonicalV03MediaType(string $fixture): void
    {
        $original = $this->fixture($fixture);

        fact($this->rebuild($original)->toArray()['mediaType'])->is('application/vnd.dev.sigstore.bundle.v0.3+json');
        fact($original['mediaType'])->is('application/vnd.dev.sigstore.bundle.v0.3+json');
    }

    /** Rebuild a bundle from the components of a parsed real bundle. */
    private function rebuild(array $bundle): BundleBuilder
    {
        $material = $bundle['verificationMaterial'];

        $builder = isset($bundle['dsseEnvelope'])
            ? BundleBuilder::forDsse(Envelope::fromArray($bundle['dsseEnvelope']))
            : BundleBuilder::forMessageSignature($this->messageSignature($bundle['messageSignature']));

        $builder->withCertificate(base64_decode($material['certificate']['rawBytes'], true));

        foreach ($material['tlogEntries'] as $entry) {
            $builder->addTransparencyLogEntry($this->tlogEntry($entry));
        }

        foreach ($material['timestampVerificationData']['rfc3161Timestamps'] ?? [] as $token) {
            $builder->addRfc3161Timestamp(base64_decode($token['signedTimestamp'], true));
        }

        return $builder;
    }

    /** @param array<string, mixed> $ms */
    private function messageSignature(array $ms): MessageSignature
    {
        return new MessageSignature(
            algorithm: HashAlgorithm::from($ms['messageDigest']['algorithm']),
            digest: base64_decode($ms['messageDigest']['digest'], true),
            signature: base64_decode($ms['signature'], true),
        );
    }

    /** @param array<string, mixed> $entry */
    private function tlogEntry(array $entry): TransparencyLogEntry
    {
        $promise = $entry['inclusionPromise']['signedEntryTimestamp'] ?? null;

        return new TransparencyLogEntry(
            logIndex: (int) $entry['logIndex'],
            logId: base64_decode($entry['logId']['keyId'], true),
            kind: $entry['kindVersion']['kind'],
            version: $entry['kindVersion']['version'],
            canonicalizedBody: base64_decode($entry['canonicalizedBody'], true),
            integratedTime: isset($entry['integratedTime']) ? (int) $entry['integratedTime'] : null,
            inclusionPromise: is_string($promise) ? base64_decode($promise, true) : null,
            inclusionProof: isset($entry['inclusionProof']) ? $this->inclusionProof($entry['inclusionProof']) : null,
        );
    }

    /** @param array<string, mixed> $proof */
    private function inclusionProof(array $proof): InclusionProof
    {
        return new InclusionProof(
            logIndex: (int) $proof['logIndex'],
            rootHash: base64_decode($proof['rootHash'], true),
            treeSize: (int) $proof['treeSize'],
            hashes: array_map(static fn (string $h): string => base64_decode($h, true), $proof['hashes']),
            checkpoint: $proof['checkpoint']['envelope'],
        );
    }

    /** @return array<string, mixed> */
    private function fixture(string $name): array
    {
        $json = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($json)->isString();
        $data = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        fact($data)->isArray();

        return $data;
    }
}
