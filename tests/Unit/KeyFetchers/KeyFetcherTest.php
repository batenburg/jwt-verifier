<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\KeyFetchers;

use Batenburg\JWTVerifier\JWKFetchers\Adaptors\Contracts\Adaptor;
use Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedResponseException;
use Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedStatusException;
use Batenburg\JWTVerifier\JWKFetchers\KeyFetcher;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

/**
 * @covers \Batenburg\JWTVerifier\JWKFetchers\KeyFetcher
 */
class KeyFetcherTest extends TestCase
{

    /**
     * @var ClientInterface|MockObject
     */
    private $client;

    /**
     * @var \PHPUnit\Framework\MockObject\MockObject|\Psr\Http\Message\ResponseInterface
     */
    private $response;

    private string $wellKnown;

    /**
     * @var Adaptor|MockObject
     */
    private $adaptor;

    private KeyFetcher $jwkFetcher;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->createMock(ClientInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->wellKnown = 'https://localhost/auth/well-known';
        $this->adaptor = $this->createMock(Adaptor::class);
        $this->jwkFetcher = new KeyFetcher(
            $this->client,
            $this->wellKnown,
            $this->adaptor
        );
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWKFetchers\KeyFetcher::getKeys
     * @throws UnexpectedResponseException
     * @throws UnexpectedStatusException
     * @throws GuzzleException
     */
    public function testGetKeys(): void
    {
        // Setup
        $this->client->expects($this->once())
            ->method('request')
            ->with('GET', $this->wellKnown)
            ->willReturn($this->response);
        $this->response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);
        $this->response->expects($this->once())
            ->method('getBody')
            ->willReturn($this->getExpectedJwksResponse($jku = 'https://oauth.lennart-peters.dev/api/v1/keys'));
        $this->adaptor->expects($this->once())
            ->method('getKeys')
            ->with($jku)
            ->willReturn($keys = ['keys']);
        // Execute
        $result = $this->jwkFetcher->getKeys();
        // Validate
        $this->assertSame($keys, $result);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWKFetchers\KeyFetcher::getKeys
     * @throws UnexpectedResponseException
     * @throws UnexpectedStatusException
     * @throws GuzzleException
     */
    public function testGetKeysWithEmptyResponse(): void
    {
        // Execute
        $this->expectException(UnexpectedResponseException::class);
        // Setup
        $this->client->expects($this->once())
            ->method('request')
            ->with('GET', $this->wellKnown)
            ->willReturn($this->response);
        $this->response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(200);
        $this->response->expects($this->once())
            ->method('getBody')
            ->willReturn('');
        // Execute
        $this->jwkFetcher->getKeys();
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWKFetchers\KeyFetcher::getKeys
     * @throws UnexpectedResponseException
     * @throws UnexpectedStatusException
     * @throws GuzzleException
     */
    public function testGetKeysWithFailingServer(): void
    {
        // Execute
        $this->expectException(UnexpectedStatusException::class);
        // Setup
        $this->client->expects($this->once())
            ->method('request')
            ->with('GET', $this->wellKnown)
            ->willReturn($this->response);
        $this->response->expects($this->once())
            ->method('getStatusCode')
            ->willReturn(400);
        // Execute
        $this->jwkFetcher->getKeys();
    }

    private function getExpectedJwksResponse(string $jwksUri): string
    {
        return '{
            "issuer": "http://oauth.lennart-peters.dev",
            "jwks_uri": "' . $jwksUri  . '"
        }';
    }
}
