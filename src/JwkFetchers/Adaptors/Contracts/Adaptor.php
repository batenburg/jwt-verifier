<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\JwkFetchers\Adaptors\Contracts;

interface Adaptor
{

    public function getKeys(string $jku): array;
}
