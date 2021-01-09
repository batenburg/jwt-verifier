<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWKFetchers;

use Batenburg\JWTVerifier\JWKFetchers\Contracts\KeyFetcher;
use Batenburg\JWTVerifier\JWKFetchers\KeyCombiner;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWKFetchers\KeyCombiner
 */
class KeyCombinerTest extends TestCase
{
    /** @var KeyFetcher|MockObject */
    private $firstJwkFetcher;

    /** @var KeyFetcher|MockObject */
    private $secondJwkFetcher;

    private KeyCombiner $jwkCombiner;

    protected function setUp(): void
    {
        parent::setUp();

        $this->firstJwkFetcher = $this->createMock(KeyFetcher::class);
        $this->secondJwkFetcher = $this->createMock(KeyFetcher::class);
        $this->jwkCombiner = new KeyCombiner($this->firstJwkFetcher, $this->secondJwkFetcher);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWKFetchers\KeyFetcher::getKeys
     */
    public function testGetPems(): void
    {
        // Setup
        $expected = [
            'id-1' => 'first-key',
            'id-2' => 'second-ley',
        ];
        $this->firstJwkFetcher->expects($this->once())
            ->method('getKeys')
            ->willReturn(array_slice($expected, 0, 1));
        $this->secondJwkFetcher->expects($this->once())
            ->method('getKeys')
            ->willReturn(array_slice($expected, 1, 1));
        // Execute
        $result = $this->jwkCombiner->getKeys();
        // Validate
        $this->assertSame($expected, $result);
    }
}
