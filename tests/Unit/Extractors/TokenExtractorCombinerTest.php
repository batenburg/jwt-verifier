<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\Extractors;

use Batenburg\JWTVerifier\Extractors\Contracts\TokenExtractor;
use Batenburg\JWTVerifier\Extractors\TokenExtractorCombiner;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\Extractors\TokenExtractorCombiner
 */
class TokenExtractorCombinerTest extends TestCase
{
    /**
     * @var TokenExtractor|MockObject
     */
    private $requestExtractor;

    /**
     * @var TokenExtractor|MockObject
     */
    private $bearerExtractor;

    /**
     * @var TokenExtractorCombiner
     */
    private TokenExtractorCombiner $tokenExtractorCombiner;

    protected function setUp(): void
    {
        parent::setUp();

        $this->requestExtractor = $this->createMock(TokenExtractor::class);
        $this->bearerExtractor = $this->createMock(TokenExtractor::class);
        $this->tokenExtractorCombiner = new TokenExtractorCombiner(
            $this->requestExtractor,
            $this->bearerExtractor
        );
    }

    /**
     * @covers \Batenburg\JWTVerifier\Extractors\TokenExtractorCombiner::extract
     */
    public function testVerify(): void
    {
        // Setup
        $this->requestExtractor->expects($this->once())
            ->method('extract')
            ->willReturn($token = 'token');
        $this->bearerExtractor->expects($this->once())
            ->method('extract')
            ->willReturn(null);
        // Execute
        $result = $this->tokenExtractorCombiner->extract();
        // Validate
        $this->assertSame($token, $result);
    }

    /**
     * @covers \Batenburg\JWTVerifier\Extractors\TokenExtractorCombiner::extract
     */
    public function testVerifyWithoutToken(): void
    {
        // Setup
        $this->requestExtractor->expects($this->once())
            ->method('extract')
            ->willReturn(null);
        $this->bearerExtractor->expects($this->once())
            ->method('extract')
            ->willReturn(null);
        // Execute
        $result = $this->tokenExtractorCombiner->extract();
        // Validate
        $this->assertNull($result);
    }

    /**
     * @covers \Batenburg\JWTVerifier\Extractors\TokenExtractorCombiner::extract
     */
    public function testVerifyWithTwoTokens(): void
    {
        // Setup
        $this->requestExtractor->expects($this->once())
            ->method('extract')
            ->willReturn($tokenOne = 'token1');
        $this->bearerExtractor->expects($this->once())
            ->method('extract')
            ->willReturn($tokenTwo = 'token2');
        // Execute
        $result = $this->tokenExtractorCombiner->extract();
        // Validate
        $this->assertSame($tokenOne, $result);
    }
}
