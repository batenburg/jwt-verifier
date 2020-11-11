<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\JwkFetchers\Exceptions;

use Exception;
use Throwable;

class UnexpectedStatusException extends Exception
{
    public function __construct(string $message = 'Unexpected status.', int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
