<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Test\Unit\JwkFetchers\Exceptions;

use Batenburg\JwtVerifier\JwkFetchers\Exceptions\UnexpectedResponseException;
use Batenburg\JwtVerifier\Test\Unit\Exceptions\ExceptionTesting;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JwtVerifier\JwkFetchers\Exceptions\UnexpectedResponseException
 */
class UnexpectedResponseExceptionTest extends TestCase
{

    use ExceptionTesting;

    protected string $class = UnexpectedResponseException::class;

    protected string $message = 'Unexpected response.';
}
