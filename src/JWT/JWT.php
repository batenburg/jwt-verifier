<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWT;

final class JWT
{

    private string $jwt;

    private array $headers;

    private array $claims;

    public function __construct(string $jwt, array $headers, array $claims)
    {
        $this->jwt = $jwt;
        $this->headers = $headers;
        $this->claims = $claims;
    }

    public function getJwt(): string
    {
        return $this->jwt;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }
}
