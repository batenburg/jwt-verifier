<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\JWKFetchers\Adaptors;

use Base64Url\Base64Url;
use Batenburg\JWTVerifier\JWKFetchers\Adaptors\Contracts\Adaptor;
use Brick\Math\BigInteger;
use Exception;
use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\NullObject;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\Sequence;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JKUFactory;

class JWTFrameworkAdaptor implements Adaptor
{
    private JKUFactory $JKUFactory;

    private ?Sequence $sequence = null;

    public function __construct(JKUFactory $JKUFactory)
    {
        $this->JKUFactory = $JKUFactory;
    }

    /**
     * @inheritDoc
     */
    public function getKeys(string $jku): array
    {
        return array_map([$this, 'convertToPem'], $this->JKUFactory->loadFromUrl($jku)->all());
    }

    /**
     * @param JWK $key
     * @return string
     * @throws Exception
     */
    private function convertToPem(JWK $key): string
    {
        $kty = $key->get('kty');

        if ($kty === 'RSA') {
            return $this->getPem($key);
        }

        throw new InvalidArgumentException('Not a RSA or EC key');
    }

    /**
     * @param JWK $key
     * @return string
     * @throws Exception
     */
    private function getPem(JWK $key): string
    {
        if ($this->sequence === null) {
            $this->sequence = new Sequence();

            $this->initPublicKey($key->get('n'), $key->get('e'));
        }

        $result = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $result .= chunk_split(base64_encode($this->sequence->getBinary()), 64, PHP_EOL);
        $result .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $result;
    }

    /**
     * @param string $nValue
     * @param string $eValue
     * @throws Exception
     */
    private function initPublicKey(string $nValue, string $eValue): void
    {
        $oid_sequence = new Sequence();
        $oid_sequence->addChild(new ObjectIdentifier('1.2.840.113549.1.1.1'));
        $oid_sequence->addChild(new NullObject());
        $this->sequence->addChild($oid_sequence);
        $n = new Integer($this->fromBase64ToInteger($nValue));
        $e = new Integer($this->fromBase64ToInteger($eValue));
        $key_sequence = new Sequence();
        $key_sequence->addChild($n);
        $key_sequence->addChild($e);
        $key_bit_string = new BitString(bin2hex($key_sequence->getBinary()));
        $this->sequence->addChild($key_bit_string);
    }

    private function fromBase64ToInteger(string $value): string
    {
        $hex = current(unpack('H*', Base64Url::decode($value)));

        return BigInteger::fromBase($hex, 16)->toBase(10);
    }
}
