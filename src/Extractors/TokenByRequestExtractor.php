<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Extractors;

use Batenburg\JwtVerifier\Extractors\Contracts\TokenExtractor;
use Symfony\Component\HttpFoundation\Request;

class TokenByRequestExtractor implements TokenExtractor
{

    public const QUERY_KEY = 'access_token';

    private Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function extract(): ?string
    {
        return $this->request->request->get(self::QUERY_KEY);
    }
}
