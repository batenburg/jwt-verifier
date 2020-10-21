<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Extractors\Contracts;

interface TokenExtractor
{

    public function extract(): ?string;
}
