<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWKFetchers\Contracts;

interface KeyFetcher
{
    /**
     * @return string[]
     */
    public function getKeys(): array;
}
