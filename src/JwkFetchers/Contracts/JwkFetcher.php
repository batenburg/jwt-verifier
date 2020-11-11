<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\JwkFetchers\Contracts;

interface JwkFetcher
{
    /**
     * @return string[]
     */
    public function getKeys(): array;
}
