<?php

declare(strict_types=1);

namespace K2gl\SigstoreBundle\Exception;

use InvalidArgumentException;

/** Thrown when a component handed to the builder is malformed or incomplete. */
final class InvalidBundleInputException extends InvalidArgumentException implements SigstoreBundleException {}
