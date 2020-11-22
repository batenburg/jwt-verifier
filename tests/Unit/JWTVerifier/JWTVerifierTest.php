<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWTVerifier;

use Batenburg\JWTVerifier\JWT\JWT;
use Batenburg\JWTVerifier\JWTVerifier\Adaptors\Contracts\Adaptor;
use Batenburg\JWTVerifier\JWTVerifier\Exceptions\JWTVerifierException;
use Batenburg\JWTVerifier\JWTVerifier\JWTVerifier;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWTVerifier\JWTVerifier
 */
class JWTVerifierTest extends TestCase
{

    private string $privateKey = '-----BEGIN ENCRYPTED PRIVATE KEY-----
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
cYgvlZCGl5xHfL7+IRNCuRYV4Q==
-----END ENCRYPTED PRIVATE KEY-----
';

    private string $passphrase = 'superSecret';

    /**
     * @var string[]
     */
    private array $keys = [
        '5550f67f-e228-4857-a0f8-7c2feb9e16b7' => '-----BEGIN PUBLIC KEY-----
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
-----END PUBLIC KEY-----
'
    ];

    /**
     * @var string[]
     */
    private array $knownClientIssuers = [
        'oauth.lennart.peters' => '47beff72-b006-48f7-9816-4c8a46e22abe'
    ];

    /**
     * @var Adaptor|MockObject
     */
    private $adaptor;

    private JWTVerifier $jwtVerifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->adaptor = $this->createMock(Adaptor::class);
        $this->jwtVerifier = new JWTVerifier($this->keys, $this->knownClientIssuers, $this->adaptor);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\JWTVerifier::verify
     * @throws JWTVerifierException
     */
    public function testEmptyToken(): void
    {
        // Expectation
        $this->expectException(JWTVerifierException::class);
        // Execute
        $this->jwtVerifier->verify('');
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\JWTVerifier::verify
     * @throws JWTVerifierException
     */
    public function testWithoutClientIssuer(): void
    {
        // Expectation
        $this->expectException(JWTVerifierException::class);
        // Setup
        $claims = [];
        $headers = [];
        $token = $this->getToken($claims, $headers);
        $this->adaptor->expects($this->once())
            ->method('decode')
            ->with($token, $this->keys)
            ->willReturn($jwt = new JWT($token, $claims));
        // Execute
        $this->jwtVerifier->verify($token);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\JWTVerifier::verify
     * @throws JWTVerifierException
     */
    public function testUnknownClientIssuer(): void
    {
        // Expectation
        $this->expectException(JWTVerifierException::class);
        // Setup
        $claims = [
            'iss' => 'non.existing',
            'cid' => 'not-set'
        ];
        $headers = [];
        $token = $this->getToken($claims, $headers);
        $this->adaptor->expects($this->once())
            ->method('decode')
            ->with($token, $this->keys)
            ->willReturn($jwt = new JWT($token, $claims));
        // Execute
        $this->jwtVerifier->verify($token);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWTVerifier\JWTVerifier::verify
     * @throws JWTVerifierException
     */
    public function testVerify(): void
    {
        // Setup
        $claims = [
            'iss' => 'oauth.lennart.peters',
            'cid' => '47beff72-b006-48f7-9816-4c8a46e22abe'
        ];
        $headers = [];
        $token = $this->getToken($claims, $headers);
        $this->adaptor->expects($this->once())
            ->method('decode')
            ->with($token, $this->keys)
            ->willReturn($jwt = new JWT($token, $claims));
        // Execute
        $result = $this->jwtVerifier->verify($token);
        // Validate
        $this->assertSame($jwt, $result);
    }

    private function getToken(array $claims, array $headers): string
    {
        $builder = (new Builder());

        foreach ($claims as $name => $value) {
            $builder->withClaim($name, $value);
        }

        foreach ($headers as $name => $value) {
            $builder->withHeader($name, $value);
        }

        return $builder->getToken(new Sha512, new Key($this->privateKey, $this->passphrase))
            ->__toString();
    }
}
