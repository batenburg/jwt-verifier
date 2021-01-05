<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWKFetchers;

use Batenburg\JWTVerifier\JWKFetchers\Adaptors\Contracts\Adaptor;
use Batenburg\JWTVerifier\JWKFetchers\Contracts\KeyFetcher as KeyFetcherInterface;
use Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedResponseException;
use Batenburg\JWTVerifier\JWKFetchers\Exceptions\UnexpectedStatusException;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

class KeyFetcher implements KeyFetcherInterface
{
    private ClientInterface $client;

    private string $wellKnown;

    private Adaptor $adaptor;

    public function __construct(
        ClientInterface $client,
        string $wellKnown,
        Adaptor $adaptor
    ) {
        $this->client = $client;
        $this->wellKnown = $wellKnown;
        $this->adaptor = $adaptor;
    }

    /**
     * @return string[]
     * @throws UnexpectedResponseException
     * @throws UnexpectedStatusException
     * @throws GuzzleException
     */
    public function getKeys(): array
    {
        return $this->adaptor->getKeys(
            $this->getKeysUri()
        );
    }

    /**
     * @return string
     * @throws UnexpectedResponseException
     * @throws UnexpectedStatusException
     * @throws GuzzleException
     */
    protected function getKeysUri(): string
    {
        $response = $this->client->request('GET', $this->wellKnown);

        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedStatusException;
        }

        $object = json_decode($response->getBody());

        if (! isset($object->jwks_uri)) {
            throw new UnexpectedResponseException;
        }

        return $object->jwks_uri;
    }
}
