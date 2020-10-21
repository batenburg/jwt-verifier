<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Test\Unit\Extractors;

use Batenburg\JwtVerifier\Extractors\TokenByBearerExtractor;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * @covers \Batenburg\JwtVerifier\Extractors\TokenByBearerExtractor
 */
class TokenByBearerExtractorTest extends TestCase
{

    /**
     * @covers \Batenburg\JwtVerifier\Extractors\TokenByBearerExtractor::extract
     */
    public function testExtract(): void
    {
        // Setup
        $token = 'token';
        $request = new Request();
        $request->headers->set('Authorization', "Bearer {$token}");
        $tokenByBearerExtractor = new TokenByBearerExtractor($request);
        // Execute
        $result = $tokenByBearerExtractor->extract();
        // Validate
        $this->assertSame($token, $result);
    }

    /**
     * @covers \Batenburg\JwtVerifier\Extractors\TokenByBearerExtractor::extract
     */
    public function testExtractWithoutAuthorizationHeader(): void
    {
        // Setup
        $request = new Request();
        $tokenByBearerExtractor = new TokenByBearerExtractor($request);
        // Execute
        $result = $tokenByBearerExtractor->extract();
        // Validate
        $this->assertNull($result);
    }

    /**
     * @covers \Batenburg\JwtVerifier\Extractors\TokenByBearerExtractor::extract
     */
    public function testExtractFails(): void
    {
        // Setup
        $request = new Request();
        $request->headers->set('Authorization', '');
        $tokenByBearerExtractor = new TokenByBearerExtractor($request);
        // Execute
        $result = $tokenByBearerExtractor->extract();
        // Validate
        $this->assertNull($result);
    }
}
