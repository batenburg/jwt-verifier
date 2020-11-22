<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWKFetchers\Exceptions;

use Exception;
use Throwable;

class UnexpectedResponseException extends Exception
{

    public function __construct(string $message = 'Unexpected response.', int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
