<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Extractors;

use Batenburg\JWTVerifier\Extractors\Contracts\TokenExtractor;
use Symfony\Component\HttpFoundation\Request;

class TokenByBearerExtractor implements TokenExtractor
{
    private Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function extract(): ?string
    {
        $header = $this->request->headers->get('Authorization', '');

        if (strpos($header, 'Bearer ') === false) {
            return null;
        }

        return str_replace('Bearer ', '', $header);
    }
}
