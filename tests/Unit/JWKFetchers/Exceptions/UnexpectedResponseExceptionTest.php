<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWKFetchers\Exceptions;

use Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedResponseException;
use Batenburg\JWTVerifier\Test\Unit\Exceptions\ExceptionTesting;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedResponseException
 */
class UnexpectedResponseExceptionTest extends TestCase
{
    use ExceptionTesting;

    protected string $class = UnexpectedResponseException::class;

    protected string $message = 'Unexpected response.';
}
