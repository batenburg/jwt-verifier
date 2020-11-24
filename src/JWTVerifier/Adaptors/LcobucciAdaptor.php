<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWTVerifier\Adaptors;

use Batenburg\JWTVerifier\JWT\JWT;
use Batenburg\JWTVerifier\JWTVerifier\Adaptors\Contracts\Adaptor;
use Batenburg\JWTVerifier\JWTVerifier\Exceptions\JWTVerifierException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

class LcobucciAdaptor implements Adaptor
{
    /**
     * @var Signer[]
     */
    private array $signers;

    public function __construct(Signer ...$signers)
    {
        $this->signers = $signers;
    }

    /**
     * @param string $jwt
     * @param array $keys
     * @return JWT
     * @throws JWTVerifierException
     */
    public function decode(string $jwt, array $keys): JWT
    {
        if ($jwt === '') {
            throw new JWTVerifierException('No token provided.');
        }

        $decoded = (new Parser())->parse($jwt);

        if (!$decoded->hasHeader('kid')) {
            throw new JWTVerifierException('No KID set.');
        }

        if (!array_key_exists($decoded->getHeader('kid'), $keys)) {
            throw new JWTVerifierException('No key found');
        }

        if (!$decoded->hasHeader('alg')) {
            throw new JWTVerifierException('Algorithm not set.');
        }

        $signers = array_filter(
            $this->signers,
            fn (Signer $signer) => $signer->getAlgorithmId() === $decoded->getHeader('alg')
        );

        if (!$signer = reset($signers)) {
            throw new JWTVerifierException('No signer found.');
        }

        if (!$decoded->verify($signer, new Key($keys[$decoded->getHeader('kid')]))) {
            throw new JWTVerifierException('Invalid signature.');
        }

        return new JWT(
            $jwt,
            $decoded->getHeaders(),
            $decoded->getClaims()
        );
    }
}
