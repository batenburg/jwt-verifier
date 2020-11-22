<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Extractors\Contracts;

interface TokenExtractor
{

    public function extract(): ?string;
}
