<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\JwkFetchers;

use Batenburg\JwtVerifier\JwkFetchers\Contracts\JwkFetcher as JwkFetcherInterface;

class JwkCombiner implements JwkFetcherInterface
{

    private array $fetchers;

    public function __construct(JwkFetcherInterface ...$fetchers)
    {
        $this->fetchers = $fetchers;
    }

    public function getKeys(): array
    {
        $keys = [];
        foreach ($this->fetchers as $fetcher) {
            $keys += $fetcher->getKeys();
        }
        return $keys;
    }
}
