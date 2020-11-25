<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWTVerifier\Adaptors;

use Batenburg\JWTVerifier\JWT\JWT;
use Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor;
use Batenburg\JWTVerifier\JWTVerifier\Exceptions\JWTVerifierException;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor
 */
class LcobucciAdaptorTest extends TestCase
{

    private string $privateKey = '-----BEGIN ENCRYPTED PRIVATE KEY-----
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
1RI2RJMmKVVS7QU7tpRYdcp8aA==
-----END ENCRYPTED PRIVATE KEY-----';

    private string $passphrase = 'secret';

    private string $publicKey = '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo5ENhjCNKLeowYwRp8pe
KA9HjEK1zVNFJ1+V/cRqSZMF2Jf2Z86NiUfyVHXEd/o9E+aGiCqBxxbGfttDU1cv
b24DmKQlZw3UQf35zlNH5kPT2LW/x92wfZtq+DnwuzVlMz9J3M+iU8dMMSnO5ETz
O2Xlo+2xftwBmuyPQsziRCYZY5cGFssn+agzJ3dmBYYiCuV1aCciPr4bzzZjDdNR
EonsEAXuQZebuPpOh1OZCPah9xBSvHffnCichkQNNJ0Aup2rAa7g/y61FEeXJCul
fZLHtSQ65bAulPRUYSPizErqrNFoyUubpx2HTj5dfq+bWBhsnuh4WESiCfEYHRG9
m7JS+DAhm9AUE0028SevvvkRxWiR8FDKfaVgJ65ZAiFUslJ6G5OEOSuURnh5Xdrj
XemhVs/pJySAmnd9JvBZ4hd2XeSuYDwg6RktS/8LKpcPjvYOhXQs5q/xK3lnu0Zu
D90nKBfuJBnEacjhKpI/8VI5BAzUCvfM/Zocp1RW4LizDFmdijwZbEuMQRGJAXFj
sqQKXrQ+vNmTd3OFwXf+yvm4SrQrgvbTTiIcfJDzCOXidayYmFejalEXE3PQRSQH
DMb3kNdwMti73k1OsYxu/9Spa/4yBkBCgCg4GOfSNYMF3q9asje0UKo/oxVx8XdA
kJ84fpSUbuYVRm7omxHTXMUCAwEAAQ==
-----END PUBLIC KEY-----';

    private string $invalidPublicKey = '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn7BH/1g0uesD//q4Osic
dibluQECSsxArFO5yKoPZbdWZQPCAU4v/fqNZ0hHKPxZXFqrH5UGZgDZjqAUUwr0
Dfbwk+7hx5jsJJXoNZazUjrDR8JaTC2aGnTFGDhflTx2hmUCkvog2yGAluk5EPib
hunIDMynMaU/IEaJmAD2ilfNQ0OORuWHm9PEzuomPnrIRyRitsx8E4d7/ngGdphq
NtBu56NX8aPrgg7ng48i6Yf43hg/A88NU4IUJsD+4sySjCP6ughLM+OFiHoG6tzZ
bzl5qDQ2ubSxx/IOamxJi7k3y1suw/ErXoC3WJZNZ9dy05pry7pKcZ7B4x4+XTEt
fusTEVC6XVjK8RTaO3nSQJuunpFs1kUjJqiwQodiU+JN9Wu5Dk1z7P0C7vSiNcRZ
/ZqrCFH1vCkPcSrw+55Jua2zaoY+eUu3BA6XXjYFJ1MFCB8esqlboTbLRnVkJ4gU
aEUXLt7ASDsenQKCFGN6mpRI9jqho8PSQrbPX0InJKLCPqa/4wUgBCt1wctyG9XC
2yysA6b9Bd86dNRbySvnT7C8HbjPWnY/ylm/GbIiXj1srtTDY2NvpCu3gUbtNLk6
AdIyGh2HZpJI3uy4uY6xs34JlNtQe+xdztJ9tdnevNVPdD26a8agdwJKjnGLfg/j
4h84g7+qf4Bpd9GRp5jqrG0CAwEAAQ==
-----END PUBLIC KEY-----';

    private LcobucciAdaptor $lcobucciAdaptor;

    protected function setUp(): void
    {
        parent::setUp();

        $this->lcobucciAdaptor = new LcobucciAdaptor(
            new Ecdsa\Sha256(),
            new Ecdsa\Sha384(),
            new Ecdsa\Sha512(),
            new Rsa\Sha256(),
            new Rsa\Sha384(),
            new Rsa\Sha512(),
        );
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     */
    public function testDecodeWithEmptyToken(): void
    {
        // Exception
        $this->expectException(JWTVerifierException::class);
        // Setup
        $jwt = '';
        $keys = [];
        // Execute
        $this->lcobucciAdaptor->decode($jwt, $keys);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     */
    public function testDecodeWithoutKid(): void
    {
        // Exception
        $this->expectException(JWTVerifierException::class);
        // Setup
        $jwt = $this->generateToken([], [], new Rsa\Sha256(), new Key($this->privateKey, $this->passphrase));
        $keys = [];
        // Execute
        $this->lcobucciAdaptor->decode($jwt, $keys);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     */
    public function testDecodeWithNonExistingKid(): void
    {
        // Exception
        $this->expectException(JWTVerifierException::class);
        // Setup
        $jwt = $this->generateToken(
            ['kid' => '5550f67f-e228-4857-a0f8-7c2feb9e16b7'],
            [],
            new Rsa\Sha256(),
            new Key($this->privateKey, $this->passphrase)
        );
        $keys = [];
        // Execute
        $this->lcobucciAdaptor->decode($jwt, $keys);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     */
    public function testDecodeWithoutAlgorithm(): void
    {
        // Exception
        $this->expectException(JWTVerifierException::class);
        // Setup
        $jwt = $this->generateToken(
            ['kid' => '5550f67f-e228-4857-a0f8-7c2feb9e16b7'],
            [],
            new Rsa\Sha256(),
            new Key($this->privateKey, $this->passphrase)
        );
        $keys = [
            '5550f67f-e228-4857-a0f8-7c2feb9e16b7' => $this->publicKey
        ];
        // Execute
        $this->lcobucciAdaptor->decode($jwt, $keys);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     */
    public function testDecodeWithUnknownAlgorithm(): void
    {
        // Exception
        $this->expectException(JWTVerifierException::class);
        // Setup
        $jwt = $this->generateToken(
            [
                'alg' => 'sha256',
                'kid' => '5550f67f-e228-4857-a0f8-7c2feb9e16b7'
            ],
            [],
            new Rsa\Sha256(),
            new Key($this->privateKey, $this->passphrase)
        );
        $keys = [
            '5550f67f-e228-4857-a0f8-7c2feb9e16b7' => $this->publicKey
        ];
        // Execute
        $this->lcobucciAdaptor->decode($jwt, $keys);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     */
    public function testDecodeWithInvalidPublicKey(): void
    {
        // Exception
        $this->expectException(JWTVerifierException::class);
        // Setup
        $jwt = $this->generateToken(
            [
                'alg' => 'RS256',
                'kid' => '5550f67f-e228-4857-a0f8-7c2feb9e16b7'
            ],
            [],
            new Rsa\Sha256(),
            new Key($this->privateKey, $this->passphrase)
        );
        $keys = [
            '5550f67f-e228-4857-a0f8-7c2feb9e16b7' => $this->invalidPublicKey
        ];
        // Execute
        $this->lcobucciAdaptor->decode($jwt, $keys);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\Adaptors\LcobucciAdaptor::decode
     * @throws JWTVerifierException
     */
    public function testDecode(): void
    {
        // Setup
        $jwt = $this->generateToken(
            $headers = [
                'alg' => 'RS256',
                'kid' => '5550f67f-e228-4857-a0f8-7c2feb9e16b7'
            ],
            $claims = [],
            new Rsa\Sha256(),
            new Key($this->privateKey, $this->passphrase)
        );
        $keys = [
            '5550f67f-e228-4857-a0f8-7c2feb9e16b7' => $this->publicKey
        ];
        // Execute
        $result = $this->lcobucciAdaptor->decode($jwt, $keys);
        // Validate
        $this->assertInstanceOf(JWT::class, $result);
        $this->assertSame($headers, $result->getHeaders());
        $this->assertSame($claims, $result->getClaims());
        $this->assertSame($jwt, $result->getJwt());
    }

    private function generateToken(array $headers, array $claims, Signer $signer, Key $key): string
    {
        $encoder = new Encoder();

        $payload = [
            $encoder->base64UrlEncode($encoder->jsonEncode($headers)),
            $encoder->base64UrlEncode($encoder->jsonEncode($claims))
        ];

        $signature = $signer->sign(implode('.', $payload), $key);

        if ($signature !== null) {
            $payload[] = $encoder->base64UrlEncode($signature);
        }

        $token = new Token($headers, $claims, $signature, $payload);

        return $token->__toString();
    }
}
