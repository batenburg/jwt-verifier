<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Test\Unit\Extractors;

use Batenburg\JwtVerifier\Extractors\TokenByRequestExtractor;
use http\Exception\InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * @covers \Batenburg\JwtVerifier\Extractors\TokenByRequestExtractor
 */
class TokenByRequestExtractorTest extends TestCase
{

    /**
     * @covers \Batenburg\JwtVerifier\Extractors\TokenByRequestExtractor::extract
     */
    public function testExtract(): void
    {
        // Setup
        $token = 'token';
        $request = new Request();
        $request->request->set('access_token', $token);
        $tokenByRequestExtractor = new TokenByRequestExtractor($request);
        // Execute
        $result = $tokenByRequestExtractor->extract();
        // Validate
        $this->assertSame($token, $result);
    }

    /**
     * @covers \Batenburg\JwtVerifier\Extractors\TokenByRequestExtractor::extract
     */
    public function testExtractWithoutAccessToken(): void
    {
        // Setup
        $request = new Request();
        $tokenByRequestExtractor = new TokenByRequestExtractor($request);
        // Execute
        $result = $tokenByRequestExtractor->extract();
        // Validate
        $this->assertNull($result);
    }
}
