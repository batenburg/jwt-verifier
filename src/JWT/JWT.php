<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWT;

final class JWT
{
    private string $jwt;

    private DataSet $headers;

    private DataSet $claims;

    public function __construct(string $jwt, DataSet $headers, DataSet $claims)
    {
        $this->jwt = $jwt;
        $this->headers = $headers;
        $this->claims = $claims;
    }

    public function getJwt(): string
    {
        return $this->jwt;
    }

    public function getHeaders(): DataSet
    {
        return $this->headers;
    }

    public function getClaims(): DataSet
    {
        return $this->claims;
    }
}
