<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Test\Unit\JwkFetchers\Exceptions;

use Batenburg\JwtVerifier\JwkFetchers\Exceptions\UnexpectedStatusException;
use Batenburg\JwtVerifier\Test\Unit\Exceptions\ExceptionTesting;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JwtVerifier\JwkFetchers\Exceptions\UnexpectedStatusException
 */
class UnexpectedStatusExceptionTest extends TestCase
{

    use ExceptionTesting;

    protected string $class = UnexpectedStatusException::class;

    protected string $message = 'Unexpected status.';
}
