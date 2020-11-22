<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\Extractors;

use Batenburg\JWTVerifier\Extractors\TokenByBearerExtractor;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * @covers \Batenburg\JWTVerifier\Extractors\TokenByBearerExtractor
 */
class TokenByBearerExtractorTest extends TestCase
{

    /**
     * @covers \Batenburg\JWTVerifier\Extractors\TokenByBearerExtractor::extract
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
     * @covers \Batenburg\JWTVerifier\Extractors\TokenByBearerExtractor::extract
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
     * @covers \Batenburg\JWTVerifier\Extractors\TokenByBearerExtractor::extract
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
