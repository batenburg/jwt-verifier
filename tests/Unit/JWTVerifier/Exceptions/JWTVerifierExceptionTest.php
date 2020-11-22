<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWTVerifier\Exceptions;

use Batenburg\JWTVerifier\JWTVerifier\Exceptions\JWTVerifierException;
use Batenburg\JWTVerifier\Test\Unit\Exceptions\ExceptionTesting;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWTVerifier\Exceptions\JWTVerifierException
 */
class JWTVerifierExceptionTest extends TestCase
{

    use ExceptionTesting;

    protected string $class = JWTVerifierException::class;

    protected string $message = 'JWT verifier exception.';
}
