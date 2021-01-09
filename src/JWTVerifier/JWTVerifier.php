<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWTVerifier;

use Batenburg\JWTVerifier\JWT\JWT;
use Batenburg\JWTVerifier\JWT\DataSet;
use Batenburg\JWTVerifier\JWTVerifier\Adaptors\Contracts\Adaptor;
use Batenburg\JWTVerifier\JWTVerifier\Exceptions\JWTVerifierException;

class JWTVerifier
{
    /** @var string[] */
    private array $keys;

    /** @var string[] */
    private array $knownClientIssuers;

    private Adaptor $adaptor;

    /**
     * @param string[] $keys
     * @param string[] $knownClientIssuers
     * @param Adaptor $adaptor
     */
    public function __construct(array $keys, array $knownClientIssuers, Adaptor $adaptor)
    {
        $this->keys = $keys;
        $this->knownClientIssuers = $knownClientIssuers;
        $this->adaptor = $adaptor;
    }

    /**
     * @param string $jwt
     * @return JWT
     * @throws JWTVerifierException
     */
    public function verify(string $jwt): JWT
    {
        if ($jwt === '') {
            throw new JWTVerifierException('No token provided.');
        }

        $decoded = $this->adaptor->decode($jwt, $this->keys);

        $this->validateClientAndIssuer($decoded->getClaims());

        return $decoded;
    }

    /**
     * @param DataSet $claims
     * @throws JWTVerifierException
     */
    private function validateClientAndIssuer(DataSet $claims): void
    {
        if (!$claims->has('cid') || !$claims->has('iss')) {
            throw new JWTVerifierException('Client ID or issuer not set.');
        }

        $knownClients = array_filter(
            $this->knownClientIssuers,
            function (string $clientId, string $issuer) use ($claims) {
                return $claims->get('cid') === $clientId && $claims->get('iss') === $issuer;
            },
            ARRAY_FILTER_USE_BOTH
        );

        if (count($knownClients) === 0) {
            throw new JWTVerifierException('Unknown client.');
        }
    }
}
