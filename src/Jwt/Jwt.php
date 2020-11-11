<?php

declare(strict_types=1);

namespace Batenburg\JwtVerifier\Jwt;

final class Jwt
{

    private string $jwt;

    private array $claims;

    public function __construct(string $jwt, array $claims)
    {
        $this->jwt = $jwt;
        $this->claims = $claims;
    }

    public function getJwt(): string
    {
        return $this->jwt;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }
}
