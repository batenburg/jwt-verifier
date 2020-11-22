<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\KeyFetchers\Adaptors;

use Batenburg\JWTVerifier\JWKFetchers\Adaptors\JWTFrameworkAdaptor;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JKUFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWKFetchers\Adaptors\JWTFrameworkAdaptor
 */
class JWTFrameworkAdaptorTest extends TestCase
{
    /**
     * @var JKUFactory|MockObject
     */
    private $jkuFactory;

    /**
     * @var JWKSet|MockObject
     */
    private $jwkSet;

    private JWTFrameworkAdaptor $jwtFrameworkAdaptor;

    protected function setUp(): void
    {
        parent::setUp();

        $this->jkuFactory = $this->createMock(JKUFactory::class);
        $this->jwkSet = $this->createMock(JWKSet::class);
        $this->jwtFrameworkAdaptor = new JWTFrameworkAdaptor($this->jkuFactory);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWKFetchers\Adaptors\JWTFrameworkAdaptor::getKeys
     */
    public function testGetKeys(): void
    {
        // Setup
        $kid = '5550f67f-e228-4857-a0f8-7c2feb9e16b7';
        $jku = 'https://localhost/api/v1/keys';
        $this->jkuFactory->expects($this->once())
            ->method('loadFromUrl')
            ->with($jku)
            ->willReturn($this->jwkSet);
        $this->jwkSet->expects($this->once())
            ->method('all')
            ->willReturn([
                $kid => new JWK([
                    'alg' => null,
                    'e' => 'AQAB',
                    'kid' => $kid,
                    'kty' => 'RSA',
                    'n' => 'o5ENhjCNKLeowYwRp8peKA9HjEK1zVNFJ1-V_cRqSZMF2Jf2Z86NiUfyVHXEd_o9E-aGiCqBxxbGfttDU1cvb24Dm' .
                        'KQlZw3UQf35zlNH5kPT2LW_x92wfZtq-DnwuzVlMz9J3M-iU8dMMSnO5ETzO2Xlo-2xftwBmuyPQsziRCYZY5cGFssn-' .
                        'agzJ3dmBYYiCuV1aCciPr4bzzZjDdNREonsEAXuQZebuPpOh1OZCPah9xBSvHffnCichkQNNJ0Aup2rAa7g_y61FEeXJ' .
                        'CulfZLHtSQ65bAulPRUYSPizErqrNFoyUubpx2HTj5dfq-bWBhsnuh4WESiCfEYHRG9m7JS-DAhm9AUE0028SevvvkRx' .
                        'WiR8FDKfaVgJ65ZAiFUslJ6G5OEOSuURnh5XdrjXemhVs_pJySAmnd9JvBZ4hd2XeSuYDwg6RktS_8LKpcPjvYOhXQs5' .
                        'q_xK3lnu0ZuD90nKBfuJBnEacjhKpI_8VI5BAzUCvfM_Zocp1RW4LizDFmdijwZbEuMQRGJAXFjsqQKXrQ-vNmTd3OFw' .
                        'Xf-yvm4SrQrgvbTTiIcfJDzCOXidayYmFejalEXE3PQRSQHDMb3kNdwMti73k1OsYxu_9Spa_4yBkBCgCg4GOfSNYMF3' .
                        'q9asje0UKo_oxVx8XdAkJ84fpSUbuYVRm7omxHTXMU',
                    'use' => 'sig',
                    'x5c' => [
                        'MIIFyDCCA7ACCQCsxzxQWl9d5DANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMC\nbmwxEjAQBgNVBAgMCW92ZXJpan' .
                        'NlbDERMA8GA1UEBwwIZW5zY2hlZGUxETAPBgNV\nBAoMCGlkZWFsZml0MRcwFQYDVQQLDA5sZW5uYXJ0IHBldGVyczEb' .
                        'MBkGA1UEAwwS\nbGVubmFydC1wZXRlcnMuZGV2MSYwJAYJKoZIhvcNAQkBFhdpbmZvQGxlbm5hcnQt\ncGV0ZXJzLmRl' .
                        'djAeFw0yMDEwMTAxNTQxMTVaFw0yMTEwMTAxNTQxMTVaMIGlMQsw\nCQYDVQQGEwJubDESMBAGA1UECAwJb3Zlcmlqc2' .
                        'VsMREwDwYDVQQHDAhlbnNjaGVk\nZTERMA8GA1UECgwIaWRlYWxmaXQxFzAVBgNVBAsMDmxlbm5hcnQgcGV0ZXJzMRsw' .
                        '\nGQYDVQQDDBJsZW5uYXJ0LXBldGVycy5kZXYxJjAkBgkqhkiG9w0BCQEWF2luZm9A\nbGVubmFydC1wZXRlcnMuZGV2' .
                        'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\nAgEAo5ENhjCNKLeowYwRp8peKA9HjEK1zVNFJ1+V/cRqSZMF2J' .
                        'f2Z86NiUfyVHXE\nd/o9E+aGiCqBxxbGfttDU1cvb24DmKQlZw3UQf35zlNH5kPT2LW/x92wfZtq+Dnw\nuzVlMz9J3M' .
                        '+iU8dMMSnO5ETzO2Xlo+2xftwBmuyPQsziRCYZY5cGFssn+agzJ3dm\nBYYiCuV1aCciPr4bzzZjDdNREonsEAXuQZeb' .
                        'uPpOh1OZCPah9xBSvHffnCichkQN\nNJ0Aup2rAa7g/y61FEeXJCulfZLHtSQ65bAulPRUYSPizErqrNFoyUubpx2HTj' .
                        '5d\nfq+bWBhsnuh4WESiCfEYHRG9m7JS+DAhm9AUE0028SevvvkRxWiR8FDKfaVgJ65Z\nAiFUslJ6G5OEOSuURnh5Xd' .
                        'rjXemhVs/pJySAmnd9JvBZ4hd2XeSuYDwg6RktS/8L\nKpcPjvYOhXQs5q/xK3lnu0ZuD90nKBfuJBnEacjhKpI/8VI5' .
                        'BAzUCvfM/Zocp1RW\n4LizDFmdijwZbEuMQRGJAXFjsqQKXrQ+vNmTd3OFwXf+yvm4SrQrgvbTTiIcfJDz\nCOXidayY' .
                        'mFejalEXE3PQRSQHDMb3kNdwMti73k1OsYxu/9Spa/4yBkBCgCg4GOfS\nNYMF3q9asje0UKo/oxVx8XdAkJ84fpSUbu' .
                        'YVRm7omxHTXMUCAwEAATANBgkqhkiG\n9w0BAQsFAAOCAgEAjGN4sSXrNI7Sgukl8Y887PeAVVXydkizP/5HajvwqW7h' .
                        'b17F\nBxxMLgTsLSAlbVKI+9NxgIYfTo2Lr9jTikvUg/QuwO9RH0ZScf1ildY/QN92JPLk\nsJomzdPfWv/gXf6MT9Yp' .
                        'dUwCYDnTfxiU1HFdrazpnePL3p0WvwWK8hjf6RvE6tF4\ngqzaCvSjnJcXvLaz843zMlGI2RQY6Ny58vDpZMB0sDIbql' .
                        'MXJOztLl8AiUXQ9D5T\nzxGKIvwCCGkAw9NMYR954qW9ReZLjCBG71heLfNAiw3w4bkd9Ug511icViCZmAqw\n7u0JU3' .
                        'N3SpPFh9vhk33zpdE8e9Fpu5l9Zfy6v6pDBHgUjE6oMMhynlKQf0Trowgo\nayGbQsP+30+ZUMwNcnbuRjKRR3+ZaFpv' .
                        'z9ezdoZZbjYXbzNB9erIuhrxRE23KhYQ\nF1bt1ywxFLni4zcUfJ8Nvpt5mCc3ouyJlzmvqd55pwGgWX/P8mELVY/d17' .
                        'yKfoBy\nya7HjHiZt/2oz5AEL7B9opXndr0Qcr1sK+gNzg1m71HBUo+D+knLGy6PvIzsALfC\nTLmhhZT+rwsiztg/W0' .
                        '408WiWbRf9AjiklBPEghoDLIOVfF5c5KHkxvBcNQjxfATV\n2jMIYyOTMEhl667b9tNUrJ9TdRlrCMcbuV8/VnQCdfGp' .
                        'amzYQ5ZMdi1gRRs=',
                    ],
                    'x5t' => '7QSbIjIGUHy3SztH9W9Yn9eLdWc',
                    'x5t#256' => '3-7CtYmoNbRPOk0oHtKLikOVkkh4Ls3fcSsi_oW_IaI',
                ])
            ]);
        // Execute
        $results = $this->jwtFrameworkAdaptor->getKeys($jku);
        // Validate
        $this->assertIsArray($results);
        $this->assertArrayHasKey($kid, $results);
        $this->assertSame($this->getExpectedPublicKey(), $results[$kid]);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWKFetchers\Adaptors\JWTFrameworkAdaptor::getKeys
     */
    public function testGetKeysFailsOnWrongKty(): void
    {
        // Exception
        $this->expectException(InvalidArgumentException::class);
        // Setup
        $kid = '5550f67f-e228-4857-a0f8-7c2feb9e16b7';
        $jku = 'https://localhost/api/v1/keys';
        $this->jkuFactory->expects($this->once())
            ->method('loadFromUrl')
            ->with($jku)
            ->willReturn($this->jwkSet);
        $this->jwkSet->expects($this->once())
            ->method('all')
            ->willReturn([
                $kid => new JWK([
                    'alg' => null,
                    'e' => 'AQAB',
                    'kid' => $kid,
                    'kty' => 'EC',
                    'n' => 'o5ENhjCNKLeowYwRp8peKA9HjEK1zVNFJ1-V_cRqSZMF2Jf2Z86NiUfyVHXEd_o9E-aGiCqBxxbGfttDU1cvb24Dm' .
                        'KQlZw3UQf35zlNH5kPT2LW_x92wfZtq-DnwuzVlMz9J3M-iU8dMMSnO5ETzO2Xlo-2xftwBmuyPQsziRCYZY5cGFssn-' .
                        'agzJ3dmBYYiCuV1aCciPr4bzzZjDdNREonsEAXuQZebuPpOh1OZCPah9xBSvHffnCichkQNNJ0Aup2rAa7g_y61FEeXJ' .
                        'CulfZLHtSQ65bAulPRUYSPizErqrNFoyUubpx2HTj5dfq-bWBhsnuh4WESiCfEYHRG9m7JS-DAhm9AUE0028SevvvkRx' .
                        'WiR8FDKfaVgJ65ZAiFUslJ6G5OEOSuURnh5XdrjXemhVs_pJySAmnd9JvBZ4hd2XeSuYDwg6RktS_8LKpcPjvYOhXQs5' .
                        'q_xK3lnu0ZuD90nKBfuJBnEacjhKpI_8VI5BAzUCvfM_Zocp1RW4LizDFmdijwZbEuMQRGJAXFjsqQKXrQ-vNmTd3OFw' .
                        'Xf-yvm4SrQrgvbTTiIcfJDzCOXidayYmFejalEXE3PQRSQHDMb3kNdwMti73k1OsYxu_9Spa_4yBkBCgCg4GOfSNYMF3' .
                        'q9asje0UKo_oxVx8XdAkJ84fpSUbuYVRm7omxHTXMU',
                    'use' => 'sig',
                    'x5c' => [
                        'MIIFyDCCA7ACCQCsxzxQWl9d5DANBgkqhkiG9w0BAQsFADCBpTELMAkGA1UEBhMC\nbmwxEjAQBgNVBAgMCW92ZXJpan' .
                        'NlbDERMA8GA1UEBwwIZW5zY2hlZGUxETAPBgNV\nBAoMCGlkZWFsZml0MRcwFQYDVQQLDA5sZW5uYXJ0IHBldGVyczEb' .
                        'MBkGA1UEAwwS\nbGVubmFydC1wZXRlcnMuZGV2MSYwJAYJKoZIhvcNAQkBFhdpbmZvQGxlbm5hcnQt\ncGV0ZXJzLmRl' .
                        'djAeFw0yMDEwMTAxNTQxMTVaFw0yMTEwMTAxNTQxMTVaMIGlMQsw\nCQYDVQQGEwJubDESMBAGA1UECAwJb3Zlcmlqc2' .
                        'VsMREwDwYDVQQHDAhlbnNjaGVk\nZTERMA8GA1UECgwIaWRlYWxmaXQxFzAVBgNVBAsMDmxlbm5hcnQgcGV0ZXJzMRsw' .
                        '\nGQYDVQQDDBJsZW5uYXJ0LXBldGVycy5kZXYxJjAkBgkqhkiG9w0BCQEWF2luZm9A\nbGVubmFydC1wZXRlcnMuZGV2' .
                        'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\nAgEAo5ENhjCNKLeowYwRp8peKA9HjEK1zVNFJ1+V/cRqSZMF2J' .
                        'f2Z86NiUfyVHXE\nd/o9E+aGiCqBxxbGfttDU1cvb24DmKQlZw3UQf35zlNH5kPT2LW/x92wfZtq+Dnw\nuzVlMz9J3M' .
                        '+iU8dMMSnO5ETzO2Xlo+2xftwBmuyPQsziRCYZY5cGFssn+agzJ3dm\nBYYiCuV1aCciPr4bzzZjDdNREonsEAXuQZeb' .
                        'uPpOh1OZCPah9xBSvHffnCichkQN\nNJ0Aup2rAa7g/y61FEeXJCulfZLHtSQ65bAulPRUYSPizErqrNFoyUubpx2HTj' .
                        '5d\nfq+bWBhsnuh4WESiCfEYHRG9m7JS+DAhm9AUE0028SevvvkRxWiR8FDKfaVgJ65Z\nAiFUslJ6G5OEOSuURnh5Xd' .
                        'rjXemhVs/pJySAmnd9JvBZ4hd2XeSuYDwg6RktS/8L\nKpcPjvYOhXQs5q/xK3lnu0ZuD90nKBfuJBnEacjhKpI/8VI5' .
                        'BAzUCvfM/Zocp1RW\n4LizDFmdijwZbEuMQRGJAXFjsqQKXrQ+vNmTd3OFwXf+yvm4SrQrgvbTTiIcfJDz\nCOXidayY' .
                        'mFejalEXE3PQRSQHDMb3kNdwMti73k1OsYxu/9Spa/4yBkBCgCg4GOfS\nNYMF3q9asje0UKo/oxVx8XdAkJ84fpSUbu' .
                        'YVRm7omxHTXMUCAwEAATANBgkqhkiG\n9w0BAQsFAAOCAgEAjGN4sSXrNI7Sgukl8Y887PeAVVXydkizP/5HajvwqW7h' .
                        'b17F\nBxxMLgTsLSAlbVKI+9NxgIYfTo2Lr9jTikvUg/QuwO9RH0ZScf1ildY/QN92JPLk\nsJomzdPfWv/gXf6MT9Yp' .
                        'dUwCYDnTfxiU1HFdrazpnePL3p0WvwWK8hjf6RvE6tF4\ngqzaCvSjnJcXvLaz843zMlGI2RQY6Ny58vDpZMB0sDIbql' .
                        'MXJOztLl8AiUXQ9D5T\nzxGKIvwCCGkAw9NMYR954qW9ReZLjCBG71heLfNAiw3w4bkd9Ug511icViCZmAqw\n7u0JU3' .
                        'N3SpPFh9vhk33zpdE8e9Fpu5l9Zfy6v6pDBHgUjE6oMMhynlKQf0Trowgo\nayGbQsP+30+ZUMwNcnbuRjKRR3+ZaFpv' .
                        'z9ezdoZZbjYXbzNB9erIuhrxRE23KhYQ\nF1bt1ywxFLni4zcUfJ8Nvpt5mCc3ouyJlzmvqd55pwGgWX/P8mELVY/d17' .
                        'yKfoBy\nya7HjHiZt/2oz5AEL7B9opXndr0Qcr1sK+gNzg1m71HBUo+D+knLGy6PvIzsALfC\nTLmhhZT+rwsiztg/W0' .
                        '408WiWbRf9AjiklBPEghoDLIOVfF5c5KHkxvBcNQjxfATV\n2jMIYyOTMEhl667b9tNUrJ9TdRlrCMcbuV8/VnQCdfGp' .
                        'amzYQ5ZMdi1gRRs=',
                    ],
                    'x5t' => '7QSbIjIGUHy3SztH9W9Yn9eLdWc',
                    'x5t#256' => '3-7CtYmoNbRPOk0oHtKLikOVkkh4Ls3fcSsi_oW_IaI',
                ])
            ]);
        // Execute
        $this->jwtFrameworkAdaptor->getKeys($jku);
    }

    private function getExpectedPublicKey(): string
    {
        return '-----BEGIN PUBLIC KEY-----
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
';
    }
}
