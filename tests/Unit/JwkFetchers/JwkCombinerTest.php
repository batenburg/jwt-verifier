<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Test\Unit\JwkFetchers;

use Batenburg\JwtVerifier\JwkFetchers\Contracts\JwkFetcher;
use Batenburg\JwtVerifier\JwkFetchers\JwkCombiner;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JwtVerifier\JwkFetchers\JwkCombiner
 */
class JwkCombinerTest extends TestCase
{

    /**
     * @var JwkFetcher|MockObject
     */
    private $firstJwkFetcher;

    /**
     * @var JwkFetcher|MockObject
     */
    private $secondJwkFetcher;

    private JwkCombiner $jwkCombiner;

    protected function setUp(): void
    {
        parent::setUp();

        $this->firstJwkFetcher = $this->createMock(JwkFetcher::class);
        $this->secondJwkFetcher = $this->createMock(JwkFetcher::class);
        $this->jwkCombiner = new JwkCombiner($this->firstJwkFetcher, $this->secondJwkFetcher);
    }

    /**
     * @covers \Batenburg\JwtVerifier\JwkFetchers\JwkCombiner::getKeys
     */
    public function testGetKeys(): void
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
            ->willReturn(array_slice($expected,1, 1));
        // Execute
        $result = $this->jwkCombiner->getKeys();
        // Validate
        $this->assertSame($expected, $result);
    }
}
