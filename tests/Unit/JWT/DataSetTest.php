<?php

declare(strict_types=1);

namespace Batenburg\JWTVerifier\Test\Unit\JWT;

use Batenburg\JWTVerifier\JWT\DataSet;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Batenburg\JWTVerifier\JWT\DataSet
 */
class DataSetTest extends TestCase
{
    private DataSet $dataSet;

    private array $parameters = [
        'cid' => '131991cd-4aa8-433b-8095-421d424a26df',
        'iss' => 'oauth.lennart.peters',
    ];

    protected function setUp(): void
    {
        parent::setUp();

        $this->dataSet = new DataSet($this->parameters);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWT\DataSet::all
     */
    public function testAll(): void
    {
        $result = $this->dataSet->all();

        $this->assertSame($this->parameters, $result);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWT\DataSet::has
     */
    public function testHas(): void
    {
        $this->assertTrue($this->dataSet->has('cid'));
        $this->assertFalse($this->dataSet->has('none'));
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWT\DataSet::get
     */
    public function testGet(): void
    {
        $result = $this->dataSet->get('cid');

        $this->assertSame($this->parameters['cid'], $result);
    }

    /**
     * @covers \Batenburg\JWTVerifier\JWT\DataSet::get
     */
    public function testGetDefault(): void
    {
        $this->assertNull($this->dataSet->get('none'));
    }
}
