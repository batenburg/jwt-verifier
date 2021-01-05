<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWKFetchers;

use Batenburg\JWTVerifier\JWKFetchers\Contracts\KeyFetcher;

class KeyCombiner implements KeyFetcher
{
    private array $fetchers;

    public function __construct(KeyFetcher...$fetchers)
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
