<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Test\Unit\JwkFetchers;

use Batenburg\JwtVerifier\JwkFetchers\Adaptors\Contracts\Adaptor;
use Batenburg\JwtVerifier\JwkFetchers\Exceptions\UnexpectedResponseException;
use Batenburg\JwtVerifier\JwkFetchers\Exceptions\UnexpectedStatusException;
use Batenburg\JwtVerifier\JwkFetchers\JwkFetcher;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

/**
 * @covers \Batenburg\JwtVerifier\JwkFetchers\JwkFetcher
 */
class JwkFetcherTest extends TestCase
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

    private JwkFetcher $jwkFetcher;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = $this->createMock(ClientInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->wellKnown = 'https://localhost/auth/well-known';
        $this->adaptor = $this->createMock(Adaptor::class);
        $this->jwkFetcher = new JwkFetcher(
            $this->client,
            $this->wellKnown,
            $this->adaptor
        );
    }

    /**
     * @covers \Batenburg\JwtVerifier\JwkFetchers\JwkFetcher::getKeys
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
            ->willReturn($this->getExpectedJwksResponse($jwksUri = 'https://oauth.lennart-peters.dev/api/v1/keys'));
        $this->adaptor->expects($this->once())
            ->method('getKeys')
            ->with($jwksUri)
            ->willReturn($keys = ['keys']);
        // Execute
        $result = $this->jwkFetcher->getKeys();
        // Validate
        $this->assertSame($keys, $result);
    }

    /**
     * @covers \Batenburg\JwtVerifier\JwkFetchers\JwkFetcher::getKeys
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
     * @covers \Batenburg\JwtVerifier\JwkFetchers\JwkFetcher::getKeys
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
