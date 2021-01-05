<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWTVerifier\Exceptions;

use Exception;
use Throwable;

class JWTVerifierException extends Exception
{
    public function __construct(string $message = 'JWT verifier exception.', int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
