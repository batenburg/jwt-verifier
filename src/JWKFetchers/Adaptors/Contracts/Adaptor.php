<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWKFetchers\Adaptors\Contracts;

interface Adaptor
{
    /**
     * @param string $jku
     * @return string[]
     */
    public function getKeys(string $jku): array;
}
