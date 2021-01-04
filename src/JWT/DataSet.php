<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWT;

final class DataSet
{
    private array $parameters;

    public function __construct(array $parameters = [])
    {
        $this->parameters = $parameters;
    }

    public function all(): array
    {
        return $this->parameters;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->parameters);
    }

    public function get(string $key, $default = null)
    {
        if (! array_key_exists($key, $this->parameters)) {
            return $default;
        }

        return $this->parameters[$key];
    }
}
