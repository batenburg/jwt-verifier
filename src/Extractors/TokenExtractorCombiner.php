<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Extractors;

use Batenburg\JWTVerifier\Extractors\Contracts\TokenExtractor;

class TokenExtractorCombiner implements TokenExtractor
{
    /** @var TokenExtractor[] */
    private array $tokenExtractors;

    public function __construct(TokenExtractor ...$tokenExtractors)
    {
        $this->tokenExtractors = $tokenExtractors;
    }

    public function extract(): ?string
    {
        $tokens = array_map(
            fn (TokenExtractor $tokenExtractor) => $tokenExtractor->extract(),
            $this->tokenExtractors
        );

        $tokens = array_filter($tokens);

        $token = reset($tokens);

        if (! $token) {
            return null;
        }

        return $token;
    }
}
