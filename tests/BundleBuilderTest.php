<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle\Tests;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Signature;
use K2gl\SigstoreBundle\Bundle;
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\Exception\InvalidBundleInputException;
use K2gl\SigstoreBundle\Exception\SigstoreBundleException;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\InclusionProof;
use K2gl\SigstoreBundle\MessageSignature;
use K2gl\SigstoreBundle\SigningIdentity;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(BundleBuilder::class)]
#[CoversClass(Bundle::class)]
#[CoversClass(SigningIdentity::class)]
#[CoversClass(MessageSignature::class)]
#[CoversClass(TransparencyLogEntry::class)]
#[CoversClass(InclusionProof::class)]
#[CoversClass(HashAlgorithm::class)]
#[CoversClass(InvalidBundleInputException::class)]
final class BundleBuilderTest extends TestCase
{
    public function testBuildsDsseBundleWithCertificate(): void
    {
        $bundle = BundleBuilder::forDsse($this->envelope())
            ->withCertificate('leaf-der')
            ->addTransparencyLogEntry($this->entry())
            ->build();

        $array = $bundle->toArray();
        fact($array['mediaType'])->is(Bundle::MEDIA_TYPE);
        fact(isset($array['dsseEnvelope']))->true();
        fact($array['verificationMaterial']['certificate']['rawBytes'])->is(base64_encode('leaf-der'));
        fact(count($array['verificationMaterial']['tlogEntries']))->is(1);
    }

    public function testBuildsMessageSignatureBundleWithCertificateChain(): void
    {
        $array = BundleBuilder::forMessageSignature($this->messageSignature())
            ->withCertificateChain(['leaf', 'intermediate', 'root'])
            ->addTransparencyLogEntry($this->entry())
            ->toArray();

        fact(isset($array['messageSignature']))->true();
        fact(count($array['verificationMaterial']['x509CertificateChain']['certificates']))->is(3);
    }

    public function testBuildsPublicKeyBundleWithTimestamp(): void
    {
        $array = BundleBuilder::forMessageSignature($this->messageSignature())
            ->withPublicKey('key-hint')
            ->addTransparencyLogEntry($this->entry())
            ->addRfc3161Timestamp('ts-token')
            ->toArray();

        fact($array['verificationMaterial']['publicKey']['hint'])->is('key-hint');
        fact($array['verificationMaterial']['timestampVerificationData']['rfc3161Timestamps'][0]['signedTimestamp'])
            ->is(base64_encode('ts-token'));
    }

    public function testInclusionPromiseWithoutProofSerialises(): void
    {
        $entry = new TransparencyLogEntry(
            logIndex: 7,
            logId: 'log',
            kind: 'hashedrekord',
            version: '0.0.1',
            canonicalizedBody: 'body',
            integratedTime: 1710869186,
            inclusionPromise: 'set-bytes',
        );

        $array = $entry->toArray();
        fact($array['integratedTime'])->is('1710869186');
        fact($array['inclusionPromise']['signedEntryTimestamp'])->is(base64_encode('set-bytes'));
        fact(isset($array['inclusionProof']))->false();
    }

    public function testRejectsMissingIdentity(): void
    {
        // act + assert
        fact(fn () => BundleBuilder::forDsse($this->envelope())->addTransparencyLogEntry($this->entry())->build())
            ->throws(InvalidBundleInputException::class);
    }

    public function testRejectsMissingTransparencyLog(): void
    {
        // act + assert
        fact(fn () => BundleBuilder::forDsse($this->envelope())->withCertificate('leaf')->build())
            ->throws(InvalidBundleInputException::class);
    }

    public function testRejectsEmptyCertificate(): void
    {
        // act + assert
        fact(static fn () => SigningIdentity::certificate(''))->throws(SigstoreBundleException::class);
    }

    public function testRejectsEmptyPublicKeyHint(): void
    {
        // act + assert
        fact(static fn () => SigningIdentity::publicKey(''))->throws(InvalidBundleInputException::class);
    }

    public function testRejectsEmptyChain(): void
    {
        // act + assert
        fact(static fn () => SigningIdentity::certificateChain([]))->throws(InvalidBundleInputException::class);
    }

    public function testRejectsWrongDigestLength(): void
    {
        // act + assert
        fact(static fn () => new MessageSignature(HashAlgorithm::SHA2_256, 'too-short', 'sig'))
            ->throws(InvalidBundleInputException::class);
    }

    public function testRejectsEmptySignature(): void
    {
        // act + assert
        fact(static fn () => new MessageSignature(HashAlgorithm::SHA2_256, str_repeat("\0", 32), ''))
            ->throws(InvalidBundleInputException::class);
    }

    public function testRejectsEmptyTimestampToken(): void
    {
        // act + assert
        fact(fn () => BundleBuilder::forMessageSignature($this->messageSignature())->addRfc3161Timestamp(''))
            ->throws(InvalidBundleInputException::class);
    }

    public function testRejectsEntryWithoutAnyProof(): void
    {
        // act + assert
        fact(static fn () => new TransparencyLogEntry(
            logIndex: 1,
            logId: 'log',
            kind: 'hashedrekord',
            version: '0.0.1',
            canonicalizedBody: 'body',
        ))->throws(InvalidBundleInputException::class);
    }

    public function testRejectsInclusionProofTreeSizeNotAfterIndex(): void
    {
        // act + assert
        fact(static fn () => new InclusionProof(logIndex: 5, rootHash: 'root', treeSize: 5, hashes: [], checkpoint: 'cp'))
            ->throws(InvalidBundleInputException::class);
    }

    public function testRejectsInclusionProofWithoutCheckpoint(): void
    {
        // act + assert
        fact(static fn () => new InclusionProof(logIndex: 1, rootHash: 'root', treeSize: 2, hashes: [], checkpoint: ''))
            ->throws(InvalidBundleInputException::class);
    }

    public function testDigestLengthPerAlgorithm(): void
    {
        fact(HashAlgorithm::SHA2_256->digestLength())->is(32);
        fact(HashAlgorithm::SHA2_384->digestLength())->is(48);
        fact(HashAlgorithm::SHA2_512->digestLength())->is(64);
    }

    private function envelope(): Envelope
    {
        return new Envelope('payload', 'application/vnd.in-toto+json', [new Signature('sig-bytes', null)]);
    }

    private function messageSignature(): MessageSignature
    {
        return new MessageSignature(HashAlgorithm::SHA2_256, str_repeat("\x11", 32), 'signature-bytes');
    }

    private function entry(): TransparencyLogEntry
    {
        return new TransparencyLogEntry(
            logIndex: 42,
            logId: 'log-id',
            kind: 'dsse',
            version: '0.0.1',
            canonicalizedBody: 'canonical-body',
            inclusionProof: new InclusionProof(
                logIndex: 42,
                rootHash: 'root-hash',
                treeSize: 43,
                hashes: ['h1', 'h2'],
                checkpoint: "origin\n43\ncp\n",
            ),
        );
    }
}
