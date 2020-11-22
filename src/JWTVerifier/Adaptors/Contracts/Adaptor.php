<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWTVerifier\Adaptors\Contracts;

use Batenburg\JWTVerifier\JWT\JWT;

interface Adaptor
{
    /**
     * @param string $jwt
     * @param string[] $keys
     * @return JWT
     */
    public function decode(string $jwt, array $keys): JWT;
}
