<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\KeyFetchers\Exceptions;

use Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedStatusException;
use Batenburg\JWTVerifier\Test\Unit\Exceptions\ExceptionTesting;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedStatusException
 */
class UnexpectedStatusExceptionTest extends TestCase
{
    use ExceptionTesting;

    protected string $class = UnexpectedStatusException::class;

    protected string $message = 'Unexpected status.';
}
