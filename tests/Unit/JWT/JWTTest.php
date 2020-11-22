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
     * @covers       \Batenburg\JWTVerifier\JWT\JWT
     * @dataProvider jwtScenarioProvider
     * @param string $jwt
     * @param array $claims
     */
    public function testAJwtIsSeededProperly(string $jwt, array $claims): void
    {
        // Setup
        $result = new JWT($jwt, $claims);
        // Validate
        $this->assertInstanceOf(JWT::class, $result);
        $this->assertSame($jwt, $result->getJwt());
        $this->assertSame($claims, $result->getClaims());
    }

    public function jwtScenarioProvider(): array
    {
        return [
            'A default token is seeded properly' => [
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJhdWQiOiJodHRwczpcL1wvYmFja2VuZC5sZW5uYXJ0LXBldGVycy5kZXYiLCJ' .
                'pc3MiOiIxMzE5OTFjZC00YWE4LTQzM2ItODA5NS00MjFkNDI0YTI2ZGYiLCJpYXQiOjE2MDM4MjQ3MDksImV4cCI6MTYwMzgyODM' .
                'wOSwic3ViIjoiMSIsInNjcCI6InJlYWQuY29yZS5lbnRpdGllcyB3cml0ZS5jb3JlLmVudGl0aWVzIHJlYWQucXVvdGF0aW9ucyB' .
                '3cml0ZS5xdW90YXRpb25zIn0.JCyNzrDIulTzCSd1tIA2pNQKk7EuGit4gpecNNU6ldFXJMiE-uBj5XZMsV4uglsx1hhhlDj_MNH' .
                'xDPkr_WD-nhWL6xIjYTwzVt6wZSW1mmD9VN6uDHQ56vQ5q4xfgsaBtB-iARbpGFI-ZZCLPrY7a7V4YenHXOQCj5t2QTQhXdHWL4j' .
                '6ZhGZK4pKbicACTGPUABXnOM4sw9ejQKIw9L8huswZ7lSn3j4PL9mOFP-LVXrdWAquw-7ybVp0NETc-s0iMlKtBXVO_ZbaCotNeq' .
                'qqDSpxJsd6s0aq5UBHmMRfuUe_z-78h9X5I1ATcmg3E2kDGkwHjM27ozZLUFnq9FpW2zZIATCfGQg7ZU94SxWD5S7WNTysUO6JEI' .
                'dIsp4J0hKBX7G08hiON9ftBJdDUqpHtuxdIA1i0CU76ZqnwrfwtEoP5ki7AO5edctIoDUNQAaKb5tBSMpYbOF7FIm7YpJgdgFJcK' .
                'qIyBvMhNgYzJFjCcmZW_DLDCh88aRTup5lZaov6VUjWfp7B_ItVIPor4bHjfwxAOvt4MdAgzPdNbMsnUz_tGVZlCeZZm8gjZPikG' .
                'QeUqZh6s2y2XfH8uEQIBe_YdpPqrF-cncTv7qWvSpYTSl_sAaBmkej29pD64ObilziPL64F60QXpKeV3Aby-UP0XRRLMYEIMn1Ew' .
                '0X5bxm-Y',
                [
                    'aud' => 'https =>//backend.lennart-peters.dev',
                    'iss' => '131991cd-4aa8-433b-8095-421d424a26df',
                    'iat' => 1603824709,
                    'exp' => 1603828309,
                    'sub' => '1',
                    'scp' => 'read.core.entities write.core.entities read.quotations write.quotations',
                ],
            ],
        ];
    }
}
