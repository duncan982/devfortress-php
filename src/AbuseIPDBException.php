<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/** Raised by {@see AbuseIPDB} on a failed request or an exhausted rate limit. */
final class AbuseIPDBException extends \RuntimeException
{
}
