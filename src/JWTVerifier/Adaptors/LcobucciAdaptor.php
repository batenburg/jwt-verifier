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

        if (!$decoded->headers()->has('kid')) {
            throw new JWTVerifierException('No KID set.');
        }

        if (!array_key_exists($decoded->headers()->get('kid'), $keys)) {
            throw new JWTVerifierException('No key found');
        }

        if (!$decoded->headers()->has('alg')) {
            throw new JWTVerifierException('Algorithm not set.');
        }

        $signers = array_filter(
            $this->signers,
            fn (Signer $signer) => $signer->getAlgorithmId() === $decoded->headers()->get('alg')
        );

        if (!$signer = reset($signers)) {
            throw new JWTVerifierException('No signer found.');
        }

        if (!$decoded->signature()->verify(
            $signer,
            $decoded->payload(),
            new Key($keys[$decoded->headers()->get('kid')])
        )) {
            throw new JWTVerifierException('Invalid signature.');
        }

        return new JWT(
            $jwt,
            $decoded->headers()->all(),
            $decoded->claims()->all()
        );
    }
}
