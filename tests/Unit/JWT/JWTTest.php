<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWT;

use Batenburg\JWTVerifier\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWT\JWT
 */
class JWTTest extends TestCase
{
    /**
     * @covers \Batenburg\JWTVerifier\JWT\JWT
     * @dataProvider jwtScenarioProvider
     * @param string $jwt
     * @param array $headers
     * @param array $claims
     */
    public function testAJwtIsSeededProperly(string $jwt, array $headers, array $claims): void
    {
        // Setup
        $result = new JWT($jwt, $headers, $claims);
        // Validate
        $this->assertInstanceOf(JWT::class, $result);
        $this->assertSame($jwt, $result->getJwt());
        $this->assertSame($headers, $result->getHeaders());
        $this->assertSame($claims, $result->getClaims());
    }

    public function jwtScenarioProvider(): array
    {
        return [
            'A default token is seeded properly' => [
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6IjU1NTBmNjdmLWUyMjgtNDg1Ny1hMGY4LTdjMmZlYjllMTZiNyJ9.eyJ' .
                'hdWQiOiJodHRwczpcL1wvYmFja2VuZC5sZW5uYXJ0LXBldGVycy5kZXYiLCJpc3MiOiJvYXV0aC5sZW5uYXJ0LnBldGVycyIsIml' .
                'hdCI6MTYwNjI0ODY4NiwiZXhwIjoxNjA2MjUyMjg2LCJzdWIiOiIxIiwic2NwIjoicmVhZC5jb3JlLmVudGl0aWVzIHdyaXRlLmN' .
                'vcmUuZW50aXRpZXMgcmVhZC5xdW90YXRpb25zIHdyaXRlLnF1b3RhdGlvbnMiLCJjaWQiOiIxMzE5OTFjZC00YWE4LTQzM2ItODA' .
                '5NS00MjFkNDI0YTI2ZGYifQ.kabTiQ5AeJvrVNHWvdLFupKujLCJ8SMaXKjhDVan6n_i57SoraMLGa76Iuv7QdDbsSO35eM9YsSL' .
                'S5pqluXC2N2aVMhdw5XPAM5l5dRMIZgPbDzrI9w_w-IztoCiD1N7M5jj_mDnKzJdjMXPNYPZkHNDqTa8AgX3UKBlFz_t0PtuqFQf' .
                'NCrk-yC8O5460FiUVga1iu3WKQEtzvnpByrBeVAzASkROH9QTYmbjJolM6Ve5KVA0qkyxJltWMCx5i8zNajLE2GEFH7l42AWTA3L' .
                'lLZE51cOmQVuACq2pSOxBCSukGBE8yC01rNISAiFDQicAi80yU5GkFsBW0rYqMb4XEgHoRpHJE7gGjVKjSPc84oAQ_3kWipsb7sc' .
                'nVOHWbZlENFpvhOjrXTbdJwTEw31CDayLiPs0Qx9ldxX39WAm4GpK-jPK8lNjJYO4FwuO0fE6wjmd0yJZJY3R7iK86m9JX7zrk7x' .
                '-ViMcb3Ul3swcwJ9VLH-MioR9ip0JT1RBiN4XsU_i65BcwtLp16MfTmr374GlfpBQzo2XGeIcD3xhCw4CXW9JuNMeyBOFi8YlP0j' .
                'izPpm6lYXGkIhdYvI83xqEDeR9-rJZPcJBbld4Idi463QOnc3Q2lOT2fW4d3n4CUx7Waf0sOZ5jmvmHmtZpcuDIbET575chnRWRC' .
                '5Zm4Ups',
                [
                    'typ' =>'JWT',
                    'alg' =>'RS512',
                    'kid' =>'5550f67f-e228-4857-a0f8-7c2feb9e16b7'
                ],
                [
                    'iss' => 'oauth.lennart.peters',
                    'iat' => 1606248686,
                    'exp' => 1606252286,
                    'sub' => '1',
                    'scp' => 'read.core.entities write.core.entities read.quotations write.quotations',
                    'cid' => '131991cd-4aa8-433b-8095-421d424a26df',
                ],
            ],
        ];
    }
}
